#!/usr/bin/env python

import ctypes
from enum import Enum, unique, auto
from functionP import gauss_invert
from pprint import pprint
import pyqbdi
from whitebox_camellia_solver import WhiteboxCamellia128Solver

import secrets

@unique
class Opcode(Enum):
    UNKNOW = auto()
    MOV = auto()
    INPUT = auto()
    OUTPUT = auto()
    RETURN = auto()
    UNITABLE = auto()
    BITABLE = auto()
    JMP = auto()
    JNE = auto()
    XOR = auto()
    AND = auto()
    OR = auto()
    ROL = auto()
    SHL = auto()
    SHR = auto()
    SETREG = auto()
    HIGHHALFBYTE = auto()
    LOWHALFBYTE = auto()


class Tracer:

    def __init__(self, path):
        self.lib = ctypes.cdll.LoadLibrary(path)
        self.addr_getSuffix = ctypes.cast(self.lib.getSuffix, ctypes.c_void_p).value
        self.addr_encryptVM = ctypes.cast(self.lib.encryptVM, ctypes.c_void_p).value

        # init VM
        self.vm = pyqbdi.VM()

        # create stack
        state = self.vm.getGPRState()
        self.stack_addr = pyqbdi.allocateVirtualStack(state, 0x100000)
        assert self.stack_addr is not None
        self.stack_range = (self.stack_addr, self.stack_addr+0x100000)

        # add instrumentation range
        self.vm.addInstrumentedModuleFromAddr(self.addr_getSuffix)

        self.suffix = self.run_getSuffix()
        self.message = b"\x00" * 8 + self.suffix

        # other variable
        self.opcodeload_addr = 0
        self.reg_range = (0, 0)
        self.nbOp = 0
        self.table_range = (0, 0)
        self.gauss_mask = None

        # auto-detect
        self.detect_read_opcode()
        self.detect_table_addr()
        self.detect_opcode()

    def __del__(self):
        pyqbdi.alignedFree(self.stack_addr)

    def reset_vm(self):
        self.vm.deleteAllInstrumentations()

    def is_stack_addr(self, addr):
        return self.stack_range[0] <= addr and addr < self.stack_range[1]

    def is_reg_addr(self, addr):
        return self.reg_range[0] <= addr and addr < self.reg_range[1]

    def is_table_addr(self, addr):
        return self.table_range[0] <= addr and addr < self.table_range[1]

    def run_getSuffix(self):
        backup_rsp = self.vm.getGPRState().rsp

        output_addr = pyqbdi.allocateMemory(8)
        asrun, ret = self.vm.call(self.addr_getSuffix, [output_addr])
        assert asrun
        suffix = pyqbdi.readMemory(output_addr, 8)
        pyqbdi.freeMemory(output_addr)

        self.vm.getGPRState().rsp = backup_rsp
        return suffix

    def run_encryptVM(self, message=None, input_addr=None, output_addr=None):
        backup_rsp = self.vm.getGPRState().rsp
        if message == None:
            message = self.message
        if input_addr == None:
            input_addr = pyqbdi.allocateMemory(16)
        if output_addr == None:
            output_addr = pyqbdi.allocateMemory(16)

        assert type(message) == bytes and len(message) == 16
        pyqbdi.writeMemory(input_addr, message)
        asrun, ret = self.vm.call(self.addr_encryptVM, [input_addr, output_addr])
        assert asrun
        cipher = pyqbdi.readMemory(output_addr, 16)
        pyqbdi.freeMemory(output_addr)
        pyqbdi.freeMemory(input_addr)

        self.vm.getGPRState().rsp = backup_rsp
        return cipher

    def detect_read_opcode(self):

        def read1CBK(vm, gpr, fpr, data):
            memaccess = vm.getInstMemoryAccess()
            for acc in memaccess:
                if acc.size != 1:
                    continue
                if hasattr(acc, 'flags') and acc.flags != pyqbdi.MEMORY_NO_FLAGS:
                    continue
                if data['tracer'].is_stack_addr(acc.accessAddress):
                    data['stack'][acc.accessAddress] = 1 + data['stack'].get(acc.accessAddress, 0)
                else:
                    if acc.type != pyqbdi.MEMORY_READ:
                        continue
                    data['addr'][acc.instAddress] = 1 + data['addr'].get(acc.instAddress, 0)

            return pyqbdi.CONTINUE

        self.reset_vm()
        data = {
            'tracer': self,
            'addr': {},
            'stack': {},
        }
        self.vm.addMemAccessCB(pyqbdi.MEMORY_READ_WRITE, read1CBK, data)
        self.run_encryptVM()

        addr_max = 0
        n_max = 0
        for a, n in data['addr'].items():
            if n > n_max:
                addr_max = a
                n_max = n
        self.opcodeload_addr = addr_max
        print("Found opcodeload instruction at: 0x{:x}".format(self.opcodeload_addr))

        compatible_addr = []
        for a, n in data['stack'].items():
            if n > 20:
                compatible_addr.append(a)
        compatible_addr.sort()

        compatible_range = []
        r = []

        for c in compatible_addr:
            if r == []:
                r.append(c)
                continue
            if c == 1 + r[-1]:
                r.append(c)
            else:
                compatible_range.append(r)
                r = [c]
        compatible_range.append(r)
        assert len(compatible_range) == 1

        self.reg_range = (compatible_range[0][0], compatible_range[0][-1]+1)
        print("Found register addr: 0x{:x} (size: {})".format(self.reg_range[0], self.reg_range[1] - self.reg_range[0]))

    def detect_table_addr(self):

        def tableCBK(vm, gpr, fpr, data):
            memaccess = vm.getInstMemoryAccess()
            assert len(memaccess) == 1
            acc = memaccess[0]
            assert acc.size == 1
            data['minAddr'] = min(data['minAddr'], acc.accessAddress)
            data['maxAddr'] = max(data['maxAddr'], acc.accessAddress)
            data['nbOp'] += 1

            return pyqbdi.CONTINUE

        self.reset_vm()
        data = {
            'nbOp' : 0,
            'minAddr': 0xffffffffffffffff,
            'maxAddr': 0,
        }
        self.vm.recordMemoryAccess(pyqbdi.MEMORY_READ)
        self.vm.addCodeAddrCB(self.opcodeload_addr, pyqbdi.PREINST, tableCBK, data)
        self.run_encryptVM()

        self.nbOp = data['nbOp']
        self.table_range = (data['minAddr'], data['maxAddr'] + 10)
        print("Found nbOp: {}".format(self.nbOp))
        print("Found Table addr: 0x{:x} (size: 0x{:x})".format(self.table_range[0], self.table_range[1] - self.table_range[0]))

    def detect_opcode(self):

        def recordMemoryAccess(vm, gpr, fpr, data):
            tracer = data['tracer']
            if data['nbOp'] == 0 or data['nbOp'] == tracer.nbOp:
                #before the first operand:
                return pyqbdi.CONTINUE

            # ignore opcodeload instruction
            #inst = vm.getInstAnalysis(pyqbdi.ANALYSIS_INSTRUCTION)
            inst = vm.getInstAnalysis()
            if inst.address == tracer.opcodeload_addr:
                return pyqbdi.CONTINUE

            memaccess = vm.getInstMemoryAccess()
            for acc in memaccess:
                if data['output_addr'] <= acc.accessAddress and acc.accessAddress < data['output_addr'] + 17:
                    assert acc.type == pyqbdi.MEMORY_WRITE
                    data['pendingOutputWrite'].append(acc)
                    continue
                elif tracer.is_table_addr(acc.accessAddress):
                    assert acc.type == pyqbdi.MEMORY_READ
                    data['pendingTableRead'].append(acc)
                    continue
                elif tracer.is_reg_addr(acc.accessAddress):
                    if acc.type == pyqbdi.MEMORY_READ:
                        data['pendingRegRead'].append(acc)
                        continue
                    elif acc.type == pyqbdi.MEMORY_WRITE:
                        data['pendingRegWrite'].append(acc)
                        continue
                    assert False
                elif tracer.is_stack_addr(acc.accessAddress) and acc.type == pyqbdi.MEMORY_READ:
                    data['pendingStackRead'].append(acc)
                    continue

            #if data['nbOp'] in [701]:
            #    print(inst.disassembly)
            #    for acc in memaccess:
            #        print(f"debugId: {data['nbOp']} type: {acc.type} addr: 0x{acc.accessAddress:x} size: {acc.size} instAddr: 0x{acc.instAddress:x} {{}}{{}}".format(
            #            "r" if tracer.is_reg_addr(acc.accessAddress) else "",
            #            "t" if tracer.is_table_addr(acc.accessAddress) else ""))
            return pyqbdi.CONTINUE

        def opcodeloadCBK(vm, gpr, fpr, data):
            tracer = data['tracer']
            memaccess = vm.getInstMemoryAccess()

            if data['nbOp'] != 0:
                opcode = data['IdOpcode'][-1]
                foundType = Opcode.UNKNOW

                diffOffset = memaccess[0].accessAddress - data['offset']
                outputWriteSize = sum([acc.size for acc in data['pendingOutputWrite']])
                regReadSize = sum([acc.size for acc in data['pendingRegRead']])
                regWriteSize = sum([acc.size for acc in data['pendingRegWrite']])
                stackReadSize = sum([acc.size for acc in data['pendingStackRead']])
                tableReadSize = sum([acc.size for acc in data['pendingTableRead']])

                if diffOffset < 1 or diffOffset > 8:
                    # Only Jump can create this difference
                    if regReadSize == 0:
                        foundType = Opcode.JMP
                    else:
                        foundType = Opcode.JNE

                elif diffOffset == 8:
                    if regReadSize == 2 and regWriteSize == 1 and tableReadSize == 8:
                        foundType = Opcode.BITABLE
                elif diffOffset == 7:
                    if regReadSize == 2 and regWriteSize == 0 and (tableReadSize == 6 or tableReadSize == 2):
                        foundType = Opcode.JNE
                    elif regReadSize == 1 and regWriteSize == 1 and tableReadSize == 7:
                        foundType = Opcode.UNITABLE
                    #else:
                    #    print(f"Error: id {data['nbOp']}, diff {diffOffset}, opcode {opcode}, regReadSize {regReadSize}, regWriteSize {regWriteSize}, tableReadSize {tableReadSize}")

                elif diffOffset == 3:
                    if outputWriteSize != 0:
                        if regReadSize == 1 and regWriteSize == 0 and tableReadSize == 2:
                            foundType = Opcode.OUTPUT
                    elif stackReadSize == 1:
                        if regReadSize == 0 and regWriteSize == 1 and tableReadSize == 2:
                            foundType = Opcode.INPUT
                    elif regReadSize == 0 and regWriteSize == 1 and tableReadSize == 2:
                        foundType = Opcode.SETREG
                    elif regReadSize == 1 and regWriteSize == 1 and tableReadSize == 2:
                        writeValue = data['pendingRegWrite'][0].value
                        readValue = data['pendingRegRead'][0].value
                        if readValue != 0:
                            foundType = Opcode.UNKNOW
                        elif readValue == writeValue and (readValue & 0xf) != writeValue:
                            foundType = Opcode.MOV
                        elif readValue != writeValue and (readValue & 0xf) == writeValue and ((readValue>>4) & 0xf) != writeValue:
                            foundType = Opcode.HIGHHALFBYTE
                        elif (readValue & 0xf) != writeValue and ((readValue>>4) & 0xf) == writeValue:
                            foundType = Opcode.LOWHALFBYTE

                elif diffOffset == 4:
                    if regReadSize == 1 and regWriteSize == 1 and tableReadSize == 2:
                        # ROL, SHL, SHR
                        foundType = Opcode.UNKNOW
                    elif regReadSize == 2 and regWriteSize == 1 and tableReadSize == 3:
                        writeValue = data['pendingRegWrite'][0].value
                        readValue0 = data['pendingRegRead'][0].value
                        readValue1 = data['pendingRegRead'][1].value
                        xorValue = readValue0 ^ readValue1
                        andValue = readValue0 & readValue1
                        orValue = readValue0 | readValue1
                        if writeValue == xorValue and writeValue != andValue and writeValue != orValue:
                            foundType = Opcode.XOR
                        elif writeValue != xorValue and writeValue == andValue and writeValue != orValue:
                            foundType = Opcode.AND
                        elif writeValue != xorValue and writeValue != andValue and writeValue == orValue:
                            foundType = Opcode.OR



                if foundType != Opcode.UNKNOW:
                    if opcode in data['opcodeType']:
                        assert data['opcodeType'][opcode] == foundType
                    else:
                        for _, v in data['opcodeType'].items():
                            assert v != foundType
                        data['opcodeType'][opcode] = foundType

            data['IdOpcode'].append(memaccess[0].value)
            data['nbOp'] += 1
            data['pendingOutputWrite'] = []
            data['pendingRegRead'] = []
            data['pendingRegWrite'] = []
            data['pendingStackRead'] = []
            data['pendingTableRead'] = []
            data['offset'] = memaccess[0].accessAddress

            if data['nbOp'] == tracer.nbOp:
                assert memaccess[0].value not in data['opcodeType']
                data['opcodeType'][memaccess[0].value] = Opcode.RETURN
            return pyqbdi.CONTINUE


        self.reset_vm()
        output_addr = pyqbdi.allocateMemory(16)
        data = {
            'tracer': self,
            'output_addr': output_addr,
            'nbOp': 0,
            'offset': 0,
            'pendingOutputWrite': [],
            'pendingRegRead': [],
            'pendingRegWrite': [],
            'pendingStackRead': [],
            'pendingTableRead': [],
            'IdOpcode': [],
            'opcodeType': {},
        }


        self.vm.addMemAccessCB(pyqbdi.MEMORY_READ_WRITE, recordMemoryAccess, data)
        self.vm.addCodeAddrCB(self.opcodeload_addr, pyqbdi.PREINST, opcodeloadCBK, data)
        self.run_encryptVM(output_addr=output_addr)

        self.opcodeType = data['opcodeType']

        self.IdOpcodes = [self.opcodeType[i] for i in data['IdOpcode']]

        #pprint(self.opcodeType)
        #pprint(self.IdOpcodes)
        #c = {}
        #for i in self.IdOpcodes:
        #    c[i] = c.get(i, 0) + 1
        #    print(c[i], i)

    def search_op(self, opcode, n):
        # return the counter when the n opcode is load by opcodeload
        # if need postInst, do +1 on the result

        count = 0
        for idx, i in enumerate(self.IdOpcodes):
            if i == opcode:
                count += 1
                if count == n:
                    return idx
        assert False


    def test_xor(self, xor_input, m=None):

        assert len(xor_input) == 8

        for i in range(8):
            assert 0 <= xor_input[i] and xor_input[i] < 256

        def opcodeCounterCBK(vm, gpr, fpr, data):
            if data['counter'] == data['nbOp']:
                tracer = data['tracer']
                for i in range(8):
                    v = pyqbdi.readMemory(tracer.reg_range[0] + 16 + i, 1)
                    pyqbdi.writeMemory(tracer.reg_range[0] + 16 + i, bytes([v[0] ^ data['xor_input'][i]]))

            data['nbOp'] += 1
            return pyqbdi.CONTINUE


        self.reset_vm()
        data = {
            'tracer': self,
            'nbOp': 0,
            'counter': self.search_op(Opcode.UNITABLE, 9),
            'xor_input': xor_input,
        }
        self.vm.addCodeAddrCB(self.opcodeload_addr, pyqbdi.PREINST, opcodeCounterCBK, data)
        return self.run_encryptVM(m)

    def generate_mask(self, oracle):

        assert oracle(self.test_xor([0 for i in range(8)])) == self.message

        def runner(s, b):
            m = [0 for i in range(8)]
            m[0] = b
            out = oracle(s.test_xor(m))
            return out[12] ^ self.message[12]

        mask = [0 for i in range(8)]
        g = gauss_invert(l=8, method=lambda b: runner(self, b))
        for pos in range(8):
            for idx, v in enumerate(g):
                if (self.suffix[(4+pos)%8] & (1<<idx)) != 0:
                    mask[pos] ^= v

        assert oracle(self.test_xor(mask))[8:] == bytes([0 for i in range(8)])

        for i in range(16):
            assert oracle(self.test_xor(mask, secrets.token_bytes(8) + self.suffix))[8:] == bytes([0 for i in range(8)])

        print("Found suffixXorMask: {}".format(mask))
        self.gauss_mask = g

        for i in range(16):
            s = secrets.token_bytes(16)
            assert oracle(self.encryptAny(s)) == s

    def encryptAny(self, message):
        m = message[:8] + self.suffix
        mask = [0 for i in range(8)]
        for pos in range(8):
            for idx, v in enumerate(self.gauss_mask):
                if ((self.suffix[(4+pos)%8] ^ message[8+((4+pos)%8)]) & (1<<idx)) != 0:
                    mask[pos] ^= v

        return self.test_xor(mask, m)

    @staticmethod
    def dump_set_contextCBK(vm, gpr, fpr, data):
        if data['dumpcounter'] == data['nbOp']:
            tracer = data['tracer']
            data['dump'] = pyqbdi.readMemory(tracer.reg_range[0], 16)

        if data['setcounter'] == data['nbOp']:
            tracer = data['tracer']
            pyqbdi.writeMemory(tracer.reg_range[0], data['set'])

        data['nbOp'] += 1
        return pyqbdi.CONTINUE

    def first_rounds(self, message):
        self.reset_vm()
        data = {
            'tracer': self,
            'nbOp': 0,
            'dumpcounter': self.search_op(Opcode.UNITABLE, 121),
            'dump': [],
            'setcounter': -1,
            'set': [],
        }
        self.vm.addCodeAddrCB(self.opcodeload_addr, pyqbdi.PREINST, self.dump_set_contextCBK, data)
        self.run_encryptVM(message)
        return list(data['dump'])

    def round15(self, message):
        self.reset_vm()
        data = {
            'tracer': self,
            'nbOp': 0,
            'dumpcounter': self.search_op(Opcode.UNITABLE, 129),
            'dump': [],
            'setcounter': self.search_op(Opcode.UNITABLE, 121),
            'set': bytes(message),
        }
        self.vm.addCodeAddrCB(self.opcodeload_addr, pyqbdi.PREINST, self.dump_set_contextCBK, data)
        self.run_encryptVM()
        return list(data['dump'])

    def round16(self, message):
        self.reset_vm()
        data = {
            'tracer': self,
            'nbOp': 0,
            'dumpcounter': self.search_op(Opcode.UNITABLE, 137),
            'dump': [],
            'setcounter': self.search_op(Opcode.UNITABLE, 129),
            'set': bytes(message),
        }
        self.vm.addCodeAddrCB(self.opcodeload_addr, pyqbdi.PREINST, self.dump_set_contextCBK, data)
        self.run_encryptVM()
        return list(data['dump'])

    def round17(self, message):
        self.reset_vm()
        data = {
            'tracer': self,
            'nbOp': 0,
            'dumpcounter': self.search_op(Opcode.UNITABLE, 145),
            'dump': [],
            'setcounter': self.search_op(Opcode.UNITABLE, 137),
            'set': bytes(message),
        }
        self.vm.addCodeAddrCB(self.opcodeload_addr, pyqbdi.PREINST, self.dump_set_contextCBK, data)
        self.run_encryptVM()
        return list(data['dump'])

    def round18(self, message):
        self.reset_vm()
        data = {
            'tracer': self,
            'nbOp': 0,
            'dumpcounter': -1,
            'dump': [],
            'setcounter': self.search_op(Opcode.UNITABLE, 145),
            'set': bytes(message),
        }
        self.vm.addCodeAddrCB(self.opcodeload_addr, pyqbdi.PREINST, self.dump_set_contextCBK, data)
        return self.run_encryptVM()


    def extract_key(self):
        solver = WhiteboxCamellia128Solver(
                lambda m: self.run_encryptVM(m),
                lambda m: self.first_rounds(m),
                lambda m: self.round15(m),
                lambda m: self.round16(m),
                lambda m: self.round17(m),
                lambda m: self.round18(m),
                self.suffix)
        key = solver.computeKey()
        solver.verify()
        print("Found Key: {}".format(key.hex()))
        return key


if __name__ == '__main__':

    import argparse
    parser = argparse.ArgumentParser()

    parser.add_argument("-i", "--input-lib", type=str, help="library path", required=True)

    args = parser.parse_args()

    tracer = Tracer(args.input_lib)

    #from client import oracle
    #tracer.generate_mask(oracle)

    tracer.extract_key()

