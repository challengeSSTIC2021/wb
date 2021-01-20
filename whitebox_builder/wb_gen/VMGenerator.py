#!/usr/bin/env python

import secrets
import random

class InstructionBase:

    def __init__(self):
        self.pos = None

    def size(self):
        raise NotImplementedError

    def generate(self, instManager):
        raise NotImplementedError

    def description(self):
        raise NotImplementedError

    def resolveSymbol(self, symbols):
        pass

    def getPosition(self):
        assert self.pos is not None
        return self.pos

    def setPosition(self, pos):
        self.pos = pos

    def getSymbol(self):
        # return (symbol/position) is defined, else None
        return None

class InstructionPosition(InstructionBase):

    def __init__(self, symbol):
        super().__init__()
        self.symbol = symbol

    def getSymbol(self):
        return (self.symbol, self.pos)

class DataInst(InstructionPosition):

    labelNextId = 0

    @classmethod
    def getNextID(cls):
        cls.labelNextId +=1
        return '_data_{}'.format(cls.labelNextId)

    def __init__(self, symbol, data):
        assert symbol.startswith('_data_')
        super().__init__(symbol)
        self.data = data

    def description(self):
        return "Table {}".format(self.symbol)

    def size(self):
        return len(self.data)

    def generate(self, instManager=None):
        return self.data

class LabelInst(InstructionPosition):

    labelNextId = 0

    @classmethod
    def getNextID(cls):
        cls.labelNextId +=1
        return '_target_{}'.format(cls.labelNextId)

    def __init__(self, symbol):
        assert symbol.startswith('_target_')
        super().__init__(symbol)

    def size(self):
        return 0

    def description(self):
        return "Label {}".format(self.symbol)

    def generate(self, instManager=None):
        return b""

class OpCodeInstruction(InstructionBase):

    def __init__(self, opcode):
        super().__init__()
        self.opcode = opcode
        assert 0 <= opcode and opcode < 256

    def size(self):
        return 1

    def generate(self, instManager=None):
        return bytes([self.opcode])

#class NopInst(OpCodeInstruction):
#
#    def __init__(self, instManager, size):
#        assert size > 0
#        super().__init__(instManager.get('nop', 4))
#        self.size = size
#
#    def size(self):
#        return self.size
#
#    def description(self):
#        return "Nop"
#
#    def generate(self, instManager=None):
#        r = super().generate()
#        return r + secrets.token_bytes(self.size - len(r))

class RetInst(OpCodeInstruction):

    instName = 'ret'
    instOperand = []

    def __init__(self, instManager, value):
        super().__init__(instManager.get(self.__class__.instName))
        self.value = value
        assert 0 <= value and value < 256

    def description(self):
        return "Ret {}".format(self.value)

    def size(self):
        return super().size() + 1

    def generate(self, instManager):
        return super().generate() + bytes([self.value])

class SetReg(OpCodeInstruction):

    instName = 'setReg'
    instOperand = ['value', 'register']

    def __init__(self, instManager, register, value):
        super().__init__(instManager.get(self.__class__.instName))
        self.value = value
        self.register = register
        assert 0 <= value and value < 256
        assert 0 <= register and register < 256

    def description(self):
        return "SetReg r{} = {}".format(self.register, self.value)

    def size(self):
        return super().size() + 2

    def generate(self, instManager):
        v = [0, 0]
        v[instManager.getPos(self.__class__.instName, 'value')] = self.value
        v[instManager.getPos(self.__class__.instName, 'register')] = self.register
        return super().generate() + bytes(v)

class MovReg(OpCodeInstruction):

    instName = 'MovReg'
    instOperand = ['regIn', 'regOut']

    def __init__(self, instManager, regIn, regOut):
        super().__init__(instManager.get(self.__class__.instName))
        self.regIn = regIn
        self.regOut = regOut
        assert 0 <= regIn and regIn < 256
        assert 0 <= regOut and regOut < 256

    def description(self):
        return "MovReg r{} = r{}".format(self.regOut, self.regIn)

    def size(self):
        return super().size() + 2

    def generate(self, instManager):
        v = [0, 0]
        v[instManager.getPos(self.__class__.instName, 'regIn')] = self.regIn
        v[instManager.getPos(self.__class__.instName, 'regOut')] = self.regOut
        return super().generate() + bytes(v)

class GetInput(OpCodeInstruction):

    instName = 'getInput'
    instOperand = ['value', 'register']

    def __init__(self, instManager, register, value):
        super().__init__(instManager.get(self.__class__.instName))
        self.value = value
        self.register = register
        assert 0 <= value and value < 256
        assert 0 <= register and register < 256

    def description(self):
        return "getInput r{} = input[{}]".format(self.register, self.value)

    def size(self):
        return super().size() + 2

    def generate(self, instManager):
        v = [0, 0]
        v[instManager.getPos(self.__class__.instName, 'value')] = self.value
        v[instManager.getPos(self.__class__.instName, 'register')] = self.register
        return super().generate() + bytes(v)

class SetOutput(OpCodeInstruction):

    instName = 'setOutput'
    instOperand = ['value', 'register']

    def __init__(self, instManager, register, value):
        super().__init__(instManager.get(self.__class__.instName))
        self.value = value
        self.register = register
        assert 0 <= value and value < 256
        assert 0 <= register and register < 256

    def description(self):
        return "setOutput output[{}] = r{}".format(self.value, self.register)

    def size(self):
        return super().size() + 2

    def generate(self, instManager):
        v = [0, 0]
        v[instManager.getPos(self.__class__.instName, 'value')] = self.value
        v[instManager.getPos(self.__class__.instName, 'register')] = self.register
        return super().generate() + bytes(v)

class UseUniTable(OpCodeInstruction):

    instName = 'UseUniTable'
    instOperand = ['regIn', 'off3', 'off2', 'off1', 'off0', 'regOut']

    def __init__(self, instManager, regIn, tableSymbol, regOut):
        super().__init__(instManager.get(self.__class__.instName))
        self.regIn = regIn
        self.regOut = regOut
        self.tableSymbol = tableSymbol
        self.tableOffset = None
        assert 0 <= regIn and regIn < 256
        assert 0 <= regOut and regOut < 256

    def description(self):
        return "UseUniTable r{} = {}[r{}]".format(self.regOut, self.tableSymbol, self.regIn)

    def size(self):
        return super().size() + 6

    def resolveSymbol(self, symbols):
        self.tableOffset = symbols[self.tableSymbol]

    def generate(self, instManager):
        assert self.tableOffset is not None
        v = [0] * 6
        v[instManager.getPos(self.__class__.instName, 'regIn')] = self.regIn
        v[instManager.getPos(self.__class__.instName, 'off3')] = (self.tableOffset >> 24)& 0xff
        v[instManager.getPos(self.__class__.instName, 'off2')] = (self.tableOffset >> 16)& 0xff
        v[instManager.getPos(self.__class__.instName, 'off1')] = (self.tableOffset >> 8)& 0xff
        v[instManager.getPos(self.__class__.instName, 'off0')] = (self.tableOffset >> 0)& 0xff
        v[instManager.getPos(self.__class__.instName, 'regOut')] = self.regOut
        return super().generate() + bytes(v)

class UseBiTable(OpCodeInstruction):

    instName = 'UseBiTable'
    instOperand = ['regIn', 'regIn2', 'off3', 'off2', 'off1', 'off0', 'regOut']

    def __init__(self, instManager, regIn, regIn2, tableSymbol, regOut):
        super().__init__(instManager.get(self.__class__.instName))
        self.regIn = regIn
        self.regIn2 = regIn2
        self.regOut = regOut
        self.tableSymbol = tableSymbol
        self.tableOffset = None
        assert 0 <= regIn and regIn < 256
        assert 0 <= regIn2 and regIn2 < 256
        assert 0 <= regOut and regOut < 256

    def description(self):
        return "UseBiTable r{} = {}[r{}*256 + r{}]".format(self.regOut, self.tableSymbol, self.regIn, self.regIn2)

    def size(self):
        return super().size() + 7

    def resolveSymbol(self, symbols):
        self.tableOffset = symbols[self.tableSymbol]

    def generate(self, instManager):
        assert self.tableOffset is not None
        v = [0] * 7
        v[instManager.getPos(self.__class__.instName, 'regIn')] = self.regIn
        v[instManager.getPos(self.__class__.instName, 'regIn2')] = self.regIn2
        v[instManager.getPos(self.__class__.instName, 'off3')] = (self.tableOffset >> 24)& 0xff
        v[instManager.getPos(self.__class__.instName, 'off2')] = (self.tableOffset >> 16)& 0xff
        v[instManager.getPos(self.__class__.instName, 'off1')] = (self.tableOffset >> 8)& 0xff
        v[instManager.getPos(self.__class__.instName, 'off0')] = (self.tableOffset >> 0)& 0xff
        v[instManager.getPos(self.__class__.instName, 'regOut')] = self.regOut
        return super().generate() + bytes(v)

class GetHighHalfByte(OpCodeInstruction):

    instName = 'GetHighHalfByte'
    instOperand = ['regIn', 'regOut']

    def __init__(self, instManager, regIn, regOut):
        super().__init__(instManager.get(self.__class__.instName))
        self.regIn = regIn
        self.regOut = regOut
        assert 0 <= regIn and regIn < 256
        assert 0 <= regOut and regOut < 256

    def description(self):
        return "GetHighHalfByte r{} = (r{} >> 4) & 0xf".format(self.regOut, self.regIn)

    def size(self):
        return super().size() + 2

    def generate(self, instManager):
        v = [0, 0]
        v[instManager.getPos(self.__class__.instName, 'regIn')] = self.regIn
        v[instManager.getPos(self.__class__.instName, 'regOut')] = self.regOut
        return super().generate() + bytes(v)

class GetLowHalfByte(OpCodeInstruction):

    instName = 'GetLowHalfByte'
    instOperand = ['regIn', 'regOut']

    def __init__(self, instManager, regIn, regOut):
        super().__init__(instManager.get(self.__class__.instName))
        self.regIn = regIn
        self.regOut = regOut
        assert 0 <= regIn and regIn < 256
        assert 0 <= regOut and regOut < 256

    def description(self):
        return "GetLowHalfByte r{} = r{} & 0xf".format(self.regOut, self.regIn)

    def size(self):
        return super().size() + 2

    def generate(self, instManager):
        v = [0, 0]
        v[instManager.getPos(self.__class__.instName, 'regIn')] = self.regIn
        v[instManager.getPos(self.__class__.instName, 'regOut')] = self.regOut
        return super().generate() + bytes(v)

class JumpInst(OpCodeInstruction):

    instName = 'JumpInst'
    instOperand = ['off3', 'off2', 'off1', 'off0']

    def __init__(self, instManager, tableSymbol):
        super().__init__(instManager.get(self.__class__.instName))
        self.tableSymbol = tableSymbol
        self.tableOffset = None

    def resolveSymbol(self, symbols):
        self.tableOffset = symbols[self.tableSymbol]

    def description(self):
        return "Jump {}".format(self.tableSymbol)

    def size(self):
        return super().size() + 4

    def generate(self, instManager):
        assert self.tableOffset is not None
        v = [0] * 4
        v[instManager.getPos(self.__class__.instName, 'off3')] = (self.tableOffset >> 24)& 0xff
        v[instManager.getPos(self.__class__.instName, 'off2')] = (self.tableOffset >> 16)& 0xff
        v[instManager.getPos(self.__class__.instName, 'off1')] = (self.tableOffset >> 8)& 0xff
        v[instManager.getPos(self.__class__.instName, 'off0')] = (self.tableOffset >> 0)& 0xff
        return super().generate() + bytes(v)

class JneInst(OpCodeInstruction):

    instName = 'JneInst'
    instOperand = ['off3', 'off2', 'off1', 'off0', 'reg1', 'reg2']

    def __init__(self, instManager, tableSymbol, reg1, reg2):
        super().__init__(instManager.get(self.__class__.instName))
        self.tableSymbol = tableSymbol
        self.tableOffset = None
        self.reg1 = reg1
        self.reg2 = reg2
        assert 0 <= reg1 and reg1 < 256
        assert 0 <= reg2 and reg2 < 256

    def resolveSymbol(self, symbols):
        self.tableOffset = symbols[self.tableSymbol]

    def description(self):
        return "Jne {} (r{} != r{})".format(self.tableSymbol, self.reg1, self.reg2)

    def size(self):
        return super().size() + 6

    def generate(self, instManager):
        assert self.tableOffset is not None
        v = [0] * 6
        v[instManager.getPos(self.__class__.instName, 'off3')] = (self.tableOffset >> 24)& 0xff
        v[instManager.getPos(self.__class__.instName, 'off2')] = (self.tableOffset >> 16)& 0xff
        v[instManager.getPos(self.__class__.instName, 'off1')] = (self.tableOffset >> 8)& 0xff
        v[instManager.getPos(self.__class__.instName, 'off0')] = (self.tableOffset >> 0)& 0xff
        v[instManager.getPos(self.__class__.instName, 'reg1')] = self.reg1
        v[instManager.getPos(self.__class__.instName, 'reg2')] = self.reg2
        return super().generate() + bytes(v)

class XorInst(OpCodeInstruction):

    instName = 'XorInst'
    instOperand = ['regIn1', 'regIn2', 'regOut']

    def __init__(self, instManager, regIn1, regIn2, regOut):
        super().__init__(instManager.get(self.__class__.instName))
        self.regIn1 = regIn1
        self.regIn2 = regIn2
        self.regOut = regOut
        assert 0 <= regIn1 and regIn1 < 256
        assert 0 <= regIn2 and regIn2 < 256
        assert 0 <= regOut and regOut < 256

    def description(self):
        return "Xor r{} = r{} ^ r{}".format(self.regOut, self.regIn1, self.regIn2)

    def size(self):
        return super().size() + 3

    def generate(self, instManager):
        v = [0] * 3
        v[instManager.getPos(self.__class__.instName, 'regIn1')] = self.regIn1
        v[instManager.getPos(self.__class__.instName, 'regIn2')] = self.regIn2
        v[instManager.getPos(self.__class__.instName, 'regOut')] = self.regOut
        return super().generate() + bytes(v)

class AndInst(OpCodeInstruction):

    instName = 'AndInst'
    instOperand = ['regIn1', 'regIn2', 'regOut']

    def __init__(self, instManager, regIn1, regIn2, regOut):
        super().__init__(instManager.get(self.__class__.instName))
        self.regIn1 = regIn1
        self.regIn2 = regIn2
        self.regOut = regOut
        assert 0 <= regIn1 and regIn1 < 256
        assert 0 <= regIn2 and regIn2 < 256
        assert 0 <= regOut and regOut < 256

    def description(self):
        return "And r{} = r{} & r{}".format(self.regOut, self.regIn1, self.regIn2)

    def size(self):
        return super().size() + 3

    def generate(self, instManager):
        v = [0] * 3
        v[instManager.getPos(self.__class__.instName, 'regIn1')] = self.regIn1
        v[instManager.getPos(self.__class__.instName, 'regIn2')] = self.regIn2
        v[instManager.getPos(self.__class__.instName, 'regOut')] = self.regOut
        return super().generate() + bytes(v)

class OrInst(OpCodeInstruction):

    instName = 'OrInst'
    instOperand = ['regIn1', 'regIn2', 'regOut']

    def __init__(self, instManager, regIn1, regIn2, regOut):
        super().__init__(instManager.get(self.__class__.instName))
        self.regIn1 = regIn1
        self.regIn2 = regIn2
        self.regOut = regOut
        assert 0 <= regIn1 and regIn1 < 256
        assert 0 <= regIn2 and regIn2 < 256
        assert 0 <= regOut and regOut < 256

    def description(self):
        return "Or r{} = r{} | r{}".format(self.regOut, self.regIn1, self.regIn2)

    def size(self):
        return super().size() + 3

    def generate(self, instManager):
        v = [0] * 3
        v[instManager.getPos(self.__class__.instName, 'regIn1')] = self.regIn1
        v[instManager.getPos(self.__class__.instName, 'regIn2')] = self.regIn2
        v[instManager.getPos(self.__class__.instName, 'regOut')] = self.regOut
        return super().generate() + bytes(v)

class RolInst(OpCodeInstruction):

    instName = 'RolInst'
    instOperand = ['regIn', 'value', 'regOut']

    def __init__(self, instManager, regIn, value, regOut):
        super().__init__(instManager.get(self.__class__.instName))
        self.regIn = regIn
        self.value = value
        self.regOut = regOut
        assert 0 <= regIn and regIn < 256
        assert 0 <= value and value < 8
        assert 0 <= regOut and regOut < 256

    def description(self):
        return "Rol r{} = (r{} >> {}) | (r{} << {})".format(self.regOut, self.regIn, self.value, self.regIn, 8 - self.value)

    def size(self):
        return super().size() + 3

    def generate(self, instManager):
        v = [0] * 3
        v[instManager.getPos(self.__class__.instName, 'regIn')] = self.regIn
        v[instManager.getPos(self.__class__.instName, 'value')] = self.value
        v[instManager.getPos(self.__class__.instName, 'regOut')] = self.regOut
        return super().generate() + bytes(v)

class ShlInst(OpCodeInstruction):

    instName = 'ShlInst'
    instOperand = ['regIn', 'value', 'regOut']

    def __init__(self, instManager, regIn, value, regOut):
        super().__init__(instManager.get(self.__class__.instName))
        self.regIn = regIn
        self.value = value
        self.regOut = regOut
        assert 0 <= regIn and regIn < 256
        assert 0 <= value and value < 8
        assert 0 <= regOut and regOut < 256

    def description(self):
        return "Shl r{} = (r{} >> {})".format(self.regOut, self.regIn, self.value)

    def size(self):
        return super().size() + 3

    def generate(self, instManager):
        v = [0] * 3
        v[instManager.getPos(self.__class__.instName, 'regIn')] = self.regIn
        v[instManager.getPos(self.__class__.instName, 'value')] = self.value
        v[instManager.getPos(self.__class__.instName, 'regOut')] = self.regOut
        return super().generate() + bytes(v)

class ShrInst(OpCodeInstruction):

    instName = 'ShrInst'
    instOperand = ['regIn', 'value', 'regOut']

    def __init__(self, instManager, regIn, value, regOut):
        super().__init__(instManager.get(self.__class__.instName))
        self.regIn = regIn
        self.value = value
        self.regOut = regOut
        assert 0 <= regIn and regIn < 256
        assert 0 <= value and value < 8
        assert 0 <= regOut and regOut < 256

    def description(self):
        return "Shr r{} = (r{} << {})".format(self.regOut, self.regIn, self.value)

    def size(self):
        return super().size() + 3

    def generate(self, instManager):
        v = [0] * 3
        v[instManager.getPos(self.__class__.instName, 'regIn')] = self.regIn
        v[instManager.getPos(self.__class__.instName, 'value')] = self.value
        v[instManager.getPos(self.__class__.instName, 'regOut')] = self.regOut
        return super().generate() + bytes(v)

class InstManager:

    def __init__(self, shuffleOpCode=False, shuffleOperand=False):
        self.opcode = {}
        opcodeAvailable = list(range(256))
        if shuffleOpCode:
            random.shuffle(opcodeAvailable)

        self.operand = {}

        for cls in [RetInst, SetReg, MovReg, GetInput, SetOutput, UseUniTable, UseBiTable,
                    GetHighHalfByte, GetLowHalfByte, JumpInst, JneInst,
                    XorInst, AndInst, OrInst, RolInst, ShlInst, ShrInst]:
            self.opcode[cls.instName] = opcodeAvailable.pop(0)
            operandlist = list(range(len(cls.instOperand)))
            self.operand[cls.instName] = {}
            if shuffleOperand:
                random.shuffle(operandlist)
            for n in cls.instOperand:
                self.operand[cls.instName][n] = operandlist.pop(0)

    def get(self, name, index=None):
        return self.opcode[name]

    def getPos(self, name, op):
        return self.operand[name][op]

    def generateContext(self):
        res = {}
        for n, op in self.opcode.items():
            res['opcode_' + n] = op
        for n, pos in self.operand.items():
            for op, index in pos.items():
                res['operand_' + n + '_' + op] = index + 1

        return res





