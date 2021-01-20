#!/usr/bin/env python

import VMGenerator
import random

class Writer:

    def __init__(self, suffix, key):
        raise NotImplementedError

    def getNewRegister(self):
        raise NotImplementedError

    def writeTable(self, table):
        raise NotImplementedError

    def setRegister(self, regOut, value):
        raise NotImplementedError

    def movValue(self, regOut, regIn):
        raise NotImplementedError

    def getInput(self, regOut, offset):
        raise NotImplementedError

    def setOutput(self, offset, regIn):
        raise NotImplementedError

    def UseUniTable(self, regOut, tableID, regIn):
        raise NotImplementedError

    def UseBiTable(self, regOut, tableID, regInHigh, regInLow, sizeLow=64):
        raise NotImplementedError

    def GetHighHalfByte(self, regOut, regIn):
        raise NotImplementedError

    def GetLowHalfByte(self, regOut, regIn):
        raise NotImplementedError

    def Return(self):
        raise NotImplementedError

    def Generate(self):
        raise NotImplementedError

class PyWriter(Writer):

    def __init__(self, suffix, key):
        self.varNum = 0
        self.table = b""
        self.Indent = 4
        self.code  = "\n"
        self.code += "def get_suffix():\n"
        self.code += "    return {}\n".format(repr(bytes(suffix)))
        self.code += "\n"
        self.code += "def encrypt(message):\n"
        self.code += "    assert len(message) == 16\n"
        self.code += "    assert message[8:16] == {}\n".format(repr(bytes(suffix)))
        self.code += "    res = [0] * 16\n"

    def getNewRegister(self):
        i = self.varNum
        self.varNum += 1
        return i

    def writeTable(self, table):
        offset = len(self.table)
        self.table += bytes(table)
        return offset

    def setRegister(self, regOut, value):
        self.code += "{}v{} = {}\n".format(" " * self.Indent, regOut, value)

    def movValue(self, regOut, regIn):
        self.code += "{}v{} = v{}\n".format(" " * self.Indent, regOut, regIn)

    def getInput(self, regOut, offset):
        self.code += "{}v{} = message[{}]\n".format(" " * self.Indent, regOut, offset)

    def setOutput(self, offset, regIn):
        self.code += "{}res[{}] = v{}\n".format(" " * self.Indent, offset, regIn)

    def UseUniTable(self, regOut, tableID, regIn):
        self.code += "{}v{} = table[{} + v{}]\n".format(" " * self.Indent, regOut, tableID, regIn)

    def UseBiTable(self, regOut, tableID, regInHigh, regInLow, sizeLow=256):
        self.code += "{}v{} = table[{} + v{}*{} + v{}]\n".format(" " * self.Indent, regOut, tableID, regInHigh, sizeLow, regInLow)

    def GetHighHalfByte(self, regOut, regIn):
        self.code += "{}v{} = (v{} >> 4) & 0xf\n".format(" " * self.Indent, regOut, regIn)

    def GetLowHalfByte(self, regOut, regIn):
        self.code += "{}v{} = v{} & 0xf\n".format(" " * self.Indent, regOut, regIn)

    def Xor(self, regOut, regIn1, regIn2):
        self.code += "{}v{} = v{} ^ v{}\n".format(" " * self.Indent, regOut, regIn1, regIn2)

    def Return(self):
        self.code += "{}return bytes(res)\n".format(" " * self.Indent)

    def Generate(self):
        res  = "#!/usr/bin/env python\n\n"
        res += "table = {}\n".format(repr(self.table))
        res += self.code
        return res

    def print(self, regs):
        self.code += "{}print('{}\\n'.format({}))\n".format(
                                                    " " * self.Indent,
                                                    "".join(["{:02x}" for i in regs]),
                                                    ", ".join(["v{}".format(i) for i in regs]))


class CWriter(Writer):

    def __init__(self, suffix, key):
        assert len(suffix) == 8
        self.varNum = 0
        self.table = b""
        self.Indent = 4
        self.suffix = suffix
        self.key = key
        self.code = ""

    def getNewRegister(self):
        i = self.varNum
        self.varNum += 1
        return i

    def writeTable(self, table):
        offset = len(self.table)
        self.table += bytes(table)
        return offset

    def setRegister(self, regOut, value):
        self.code += "{}var[{}] = {};\n".format(" " * self.Indent, regOut, value)

    def movValue(self, regOut, regIn):
        self.code += "{}var[{}] = var[{}];\n".format(" " * self.Indent, regOut, regIn)

    def getInput(self, regOut, offset):
        self.code += "{}var[{}] = message[{}];\n".format(" " * self.Indent, regOut, offset)

    def setOutput(self, offset, regIn):
        self.code += "{}res[{}] = var[{}];\n".format(" " * self.Indent, offset, regIn)

    def UseUniTable(self, regOut, tableID, regIn):
        self.code += "{}var[{}] = Table[{} + var[{}]];\n".format(" " * self.Indent, regOut, tableID, regIn)

    def UseBiTable(self, regOut, tableID, regInHigh, regInLow, sizeLow=256):
        self.code += "{}var[{}] = Table[{} + var[{}]*{} + var[{}]];\n".format(" " * self.Indent, regOut, tableID, regInHigh, sizeLow, regInLow)

    def GetHighHalfByte(self, regOut, regIn):
        self.code += "{}var[{}] = (var[{}] >> 4) & 0xf;\n".format(" " * self.Indent, regOut, regIn)

    def GetLowHalfByte(self, regOut, regIn):
        self.code += "{}var[{}] = var[{}] & 0xf;\n".format(" " * self.Indent, regOut, regIn)

    def Xor(self, regOut, regIn1, regIn2):
        self.code += "{}var[{}] = var[{}] ^ var[{}];\n".format(" " * self.Indent, regOut, regIn1, regIn2)

    def Return(self):
        self.code += "{}return 1;\n".format(" " * self.Indent)

    def Generate(self):
        res  = "\n\n"
        res += "static const unsigned char Table[] = {{ {} }};\n\n".format(", ".join([repr(i) for i in self.table]))
        res += "const unsigned char Suffix[8] = {{ {} }};\n\n".format(", ".join([repr(i) for i in self.suffix]))
        res += "#ifdef TEST_VM\n"
        res += "const unsigned char Key[16] = {{ {} }};\n\n".format(", ".join([repr(i) for i in self.key]))
        res += "#endif\n"
        res += "int encryptWB(const unsigned char* message, int n, unsigned char* res) {\n"
        res += "    unsigned char var[{}] = {{0}};\n".format(self.varNum)
        res += "    int i;\n"
        res += "    if (n != 16) return 0;\n"
        res += "    for (i = 8; i<16; i++)\n"
        res += "        if (Suffix[i-8] != message[i])\n"
        res += "            return 0;\n"
        res += self.code
        res += "}\n"
        return res

class VMWriter(Writer):

    def __init__(self, suffix, key, debug=False, addRawImplem=True, shuffleOpCode=True, shuffleOperand=False):
        assert len(suffix) == 8
        self.varNum = 0
        self.varNumMax = 0
        self.bloc = []
        self.Indent = 4
        self.code = []
        self.instManager = VMGenerator.InstManager(shuffleOpCode, shuffleOperand)
        self.debug = debug
        self.suffix = suffix
        self.rawImplem = addRawImplem

    def getNewRegister(self):
        i = self.varNum
        assert i < 256
        self.varNum += 1
        self.varNumMax = max(self.varNum, self.varNumMax)
        return i

    def reinitRegister(self):
        self.varNum = 0

    def writeTable(self, table):
        name = VMGenerator.DataInst.getNextID()
        self.bloc.append([VMGenerator.DataInst(name, table)])
        return name

    def setRegister(self, regOut, value):
        self.code.append(VMGenerator.SetReg(self.instManager, regOut, value))

    def movValue(self, regOut, regIn):
        self.code.append(VMGenerator.MovReg(self.instManager, regIn, regOut))

    def getInput(self, regOut, offset):
        # The offset 0 of the input is the method called
        self.code.append(VMGenerator.GetInput(self.instManager, regOut, offset + 1))

    def setOutput(self, offset, regIn):
        self.code.append(VMGenerator.SetOutput(self.instManager, regIn, offset))

    def UseUniTable(self, regOut, tableID, regIn):
        self.code.append(VMGenerator.UseUniTable(self.instManager, regIn, tableID, regOut))

    def UseBiTable(self, regOut, tableID, regInHigh, regInLow, sizeLow=256):
        assert sizeLow == 256
        self.code.append(VMGenerator.UseBiTable(self.instManager, regInHigh, regInLow, tableID, regOut))

    def GetHighHalfByte(self, regOut, regIn):
        self.code.append(VMGenerator.GetHighHalfByte(self.instManager, regIn, regOut))

    def GetLowHalfByte(self, regOut, regIn):
        self.code.append(VMGenerator.GetLowHalfByte(self.instManager, regIn, regOut))

    def Return(self):
        self.code.append(VMGenerator.RetInst(self.instManager, 0))

    def Xor(self, regOut, regIn1, regIn2):
        self.code.append(VMGenerator.XorInst(self.instManager, regIn1, regIn2, regOut))

    def And(self, regOut, regIn1, regIn2):
        self.code.append(VMGenerator.AndInst(self.instManager, regIn1, regIn2, regOut))

    def Or(self, regOut, regIn1, regIn2):
        self.code.append(VMGenerator.OrInst(self.instManager, regIn1, regIn2, regOut))

    def Rol(self, regOut, regIn, value):
        self.code.append(VMGenerator.RolInst(self.instManager, regIn, value, regOut))

    def Shl(self, regOut, regIn, value):
        self.code.append(VMGenerator.ShlInst(self.instManager, regIn, value, regOut))

    def Shr(self, regOut, regIn, value):
        self.code.append(VMGenerator.ShrInst(self.instManager, regIn, value, regOut))

    def addWriteSuffixBloc(self):
        name = VMGenerator.LabelInst.getNextID()
        bloc = []
        bloc.append(VMGenerator.LabelInst(name))
        for i in range(len(self.suffix)):
            bloc.append(VMGenerator.SetReg(self.instManager, 0, self.suffix[i]))
            bloc.append(VMGenerator.SetOutput(self.instManager, 0, i))
        bloc.append(VMGenerator.RetInst(self.instManager, 0))
        self.bloc.append(bloc)
        return name

    def addVerifySuffixBloc(self, labelError, labelWB):

        name = VMGenerator.LabelInst.getNextID()
        bloc = []
        bloc.append(VMGenerator.LabelInst(name))
        for i in range(len(self.suffix)):
            bloc.append(VMGenerator.SetReg(self.instManager, 0, self.suffix[i]))
            bloc.append(VMGenerator.GetInput(self.instManager, 1, i + 9))
            bloc.append(VMGenerator.JneInst(self.instManager, labelError, 0, 1))
        bloc.append(VMGenerator.JumpInst(self.instManager, labelWB))
        self.bloc.append(bloc)
        return name

    def addEntryPoint(self, parameters, labelError):
        name = VMGenerator.LabelInst.getNextID()
        bloc = []
        bloc.append(VMGenerator.LabelInst(name))
        bloc.append(VMGenerator.GetInput(self.instManager, 0, 0))
        i = 0
        for param, label in parameters.items():
            i += 1
            bloc.append(VMGenerator.SetReg(self.instManager, 1, param))
            if i == len(parameters):
                bloc.append(VMGenerator.JneInst(self.instManager, labelError, 0, 1))
                bloc.append(VMGenerator.JumpInst(self.instManager, label))
            else:
                t = VMGenerator.LabelInst.getNextID()
                bloc.append(VMGenerator.JneInst(self.instManager, t, 0, 1))
                bloc.append(VMGenerator.JumpInst(self.instManager, label))
                bloc.append(VMGenerator.LabelInst(t))
        self.bloc.append(bloc)

        return name

    def SplitBlock(self, bloc):
        while len(bloc) > 40:
            label = VMGenerator.LabelInst.getNextID()
            limit = len(bloc) - 10
            if limit > 50:
                limit = 50
            splitindex = random.randint(10, limit)

            newBloc = bloc[:splitindex]
            newBloc.append(VMGenerator.JumpInst(self.instManager, label))
            self.bloc.append(newBloc)
            bloc = bloc[splitindex:]

            bloc.insert(0, VMGenerator.LabelInst(label))
        self.bloc.append(bloc)

    def Generate(self, aeskey=None):
        param_encodeVM = 0
        param_getSuffix = 1
        param_keyShedule = 2
        param_encode = 3
        param_decode = 4

        wb_code = self.code
        labelWB = VMGenerator.LabelInst.getNextID()
        wb_code.insert(0, VMGenerator.LabelInst(labelWB))
        self.SplitBlock(wb_code)
        self.code = []

        labelSuffix = self.addWriteSuffixBloc()
        labelError = VMGenerator.LabelInst.getNextID()
        labelVerifySuffix = self.addVerifySuffixBloc(labelError, labelWB)

        entries = {param_encodeVM: labelVerifySuffix, param_getSuffix: labelSuffix}
        if self.rawImplem:
            from CamelliaWriter import CamelliaWriter
            camelliaWriter = CamelliaWriter(self)

            entries[param_keyShedule] = VMGenerator.LabelInst.getNextID()
            self.code = [VMGenerator.LabelInst(entries[param_keyShedule])]
            camelliaWriter.GenerateKeyShedule()
            self.SplitBlock(self.code)

            entries[param_encode] = VMGenerator.LabelInst.getNextID()
            self.code = [VMGenerator.LabelInst(entries[param_encode])]
            camelliaWriter.GenerateEncode()
            self.SplitBlock(self.code)

            entries[param_decode] = VMGenerator.LabelInst.getNextID()
            self.code = [VMGenerator.LabelInst(entries[param_decode])]
            camelliaWriter.GenerateDecode()
            self.SplitBlock(self.code)

            self.code = []

        labelEntry = self.addEntryPoint(entries, labelError)


        blocError = []
        blocError.append(VMGenerator.LabelInst(labelError))
        blocError.append(VMGenerator.RetInst(self.instManager, 1))
        self.bloc.append(blocError)

        random.shuffle(self.bloc)

        toGen = []
        toGen.append(VMGenerator.JumpInst(self.instManager, labelEntry))
        for b in self.bloc:
            toGen.extend(b)

        # fix the position and retrieved symbol position
        offset = 0
        symbols = {}
        for inst in toGen:
            inst.setPosition(offset)
            offset += inst.size()
            s = inst.getSymbol()
            if s is not None:
                assert s[0] not in symbols
                assert s[1] is not None
                symbols[s[0]] = s[1]
        # resolv all symbols
        for inst in toGen:
            inst.resolveSymbol(symbols)

        # generate opCode
        context = self.instManager.generateContext()
        context['param_encodeVM'] = param_encodeVM
        context['param_getSuffix'] = param_getSuffix

        context['has_rawImplem'] = 1 if self.rawImplem else 0
        context['param_keyShedule'] = param_keyShedule
        context['param_encode'] = param_encode
        context['param_decode'] = param_decode

        if aeskey is not None:
            from Crypto.Cipher import AES
            from Crypto.Util import Counter
            bitcode = bytes([i for inst in toGen for i in inst.generate(self.instManager)])
            obj = AES.new(aeskey, AES.MODE_CTR, counter=Counter.new(128))
            enc_bitcode = obj.encrypt(bitcode)
            assert len(enc_bitcode) == len(bitcode)
            context['aesKey'] = ", ".join([repr(i) for i in aeskey])
            context['hasaesKey'] = "1"
        else:
            enc_bitcode = None
            context['aesKey'] = ", ".join(["0" for i in range(16)])
            context['hasaesKey'] = "0"

        if self.debug:
            bitcode = "\n"
            s = 0
            for inst in toGen:
                b = inst.generate(self.instManager)
                assert len(b) == inst.size()
                bitcode += "    // {:x}: {}\n".format(s, inst.description())
                if len(b) > 0:
                    if enc_bitcode is None:
                        bitcode += "    {},\n".format(", ".join([repr(i) for i in b]))
                    else:
                        bitcode += "    // {}\n".format(" ".join([repr(i) for i in b]))
                        bitcode += "    {},\n".format(", ".join([repr(i) for i in enc_bitcode[s:s+len(b)]]))
                s += len(b)
            if bitcode[-2:] == ",\n":
                bitcode = bitcode[:-2] + "\n"
            context['bitcode'] = bitcode
        elif enc_bitcode is not None:
            context['bitcode'] = ", ".join([repr(i) for i in enc_bitcode])
        else:
            context['bitcode'] = ", ".join([repr(i) for inst in toGen for i in inst.generate(self.instManager)])

        res = """
#include <string.h>

unsigned char Table[] __attribute__((visibility("hidden"))) = {{ {bitcode} }};

const unsigned TableSize __attribute__((visibility("hidden"))) = sizeof(Table);

#ifdef TEST_VM
const unsigned char AESKey[16] __attribute__((visibility("hidden"))) = {{ {aesKey} }};
const unsigned int hasAESKey __attribute__((visibility("hidden"))) = {hasaesKey};
#endif

static int runVM(unsigned char* input, unsigned char* output) {{
    unsigned char registers[256] = {{0}};
    int position = 0;
    unsigned int address;

    while (1) {{
        switch (Table[position]) {{
            default:
                position = position + 1;
                break;
            case {opcode_ret}:
                return Table[position + 1];
            case {opcode_setReg}:
                registers[Table[position + {operand_setReg_register}]] = Table[position + {operand_setReg_value}];
                position = position + 3;
                break;
            case {opcode_MovReg}:
                registers[Table[position + {operand_MovReg_regOut}]] = registers[Table[position + {operand_MovReg_regIn}]];
                position = position + 3;
                break;
            case {opcode_getInput}:
                registers[Table[position + {operand_getInput_register}]] = input[Table[position + {operand_getInput_value}]];
                position = position + 3;
                break;
            case {opcode_setOutput}:
                output[Table[position + {operand_setOutput_value}]] = registers[Table[position + {operand_setOutput_register}]];
                position = position + 3;
                break;
            case {opcode_UseUniTable}:
                address = Table[position + {operand_UseUniTable_off0}] | (Table[position + {operand_UseUniTable_off1}] << 8) |
                          (Table[position + {operand_UseUniTable_off2}] << 16) | (Table[position + {operand_UseUniTable_off3}] << 24);
                registers[Table[position + {operand_UseUniTable_regOut}]] = Table[address + registers[Table[position + {operand_UseUniTable_regIn}]]];
                position = position + 7;
                break;
            case {opcode_UseBiTable}:
                address = Table[position + {operand_UseBiTable_off0}] | (Table[position + {operand_UseBiTable_off1}] << 8) |
                          (Table[position + {operand_UseBiTable_off2}] << 16) | (Table[position + {operand_UseBiTable_off3}] << 24);
                registers[Table[position + {operand_UseBiTable_regOut}]] =
                                            Table[address +
                                                  registers[Table[position + {operand_UseBiTable_regIn}]]*256 +
                                                  registers[Table[position + {operand_UseBiTable_regIn2}]] ];
                position = position + 8;
                break;
            case {opcode_GetHighHalfByte}:
                registers[Table[position + {operand_GetHighHalfByte_regOut}]] = (registers[Table[position + {operand_GetHighHalfByte_regIn}]] >> 4) & 0xf;
                position = position + 3;
                break;
            case {opcode_GetLowHalfByte}:
                registers[Table[position + {operand_GetLowHalfByte_regOut}]] = registers[Table[position + {operand_GetLowHalfByte_regIn}]] & 0xf;
                position = position + 3;
                break;
            case {opcode_JumpInst}:
                position = Table[position + {operand_JumpInst_off0}] | (Table[position + {operand_JumpInst_off1}] << 8) |
                           (Table[position + {operand_JumpInst_off2}] << 16) | (Table[position + {operand_JumpInst_off3}] << 24);
                break;
            case {opcode_JneInst}:

                address = Table[position + {operand_JneInst_off0}] | (Table[position + {operand_JneInst_off1}] << 8) |
                          (Table[position + {operand_JneInst_off2}] << 16) | (Table[position + {operand_JneInst_off3}] << 24);
                if (registers[Table[position + {operand_JneInst_reg1}]] != registers[Table[position + {operand_JneInst_reg2}]])
                    position = address;
                else
                    position = position + 7;
                break;
            case {opcode_XorInst}:
                registers[Table[position + {operand_XorInst_regOut}]] = registers[Table[position + {operand_XorInst_regIn1}]] ^ registers[Table[position + {operand_XorInst_regIn2}]];
                position = position + 4;
                break;
            case {opcode_AndInst}:
                registers[Table[position + {operand_AndInst_regOut}]] = registers[Table[position + {operand_AndInst_regIn1}]] & registers[Table[position + {operand_AndInst_regIn2}]];
                position = position + 4;
                break;
            case {opcode_OrInst}:
                registers[Table[position + {operand_OrInst_regOut}]] = registers[Table[position + {operand_OrInst_regIn1}]] | registers[Table[position + {operand_OrInst_regIn2}]];
                position = position + 4;
                break;
            case {opcode_RolInst}:
                registers[Table[position + {operand_RolInst_regOut}]] =
                    ( (registers[Table[position + {operand_RolInst_regIn}]] << Table[position + {operand_RolInst_value}]) |
                      (registers[Table[position + {operand_RolInst_regIn}]] >> (8 - Table[position + {operand_RolInst_value}]))) & 0xff;
                position = position + 4;
                break;
            case {opcode_ShlInst}:
                registers[Table[position + {operand_ShlInst_regOut}]] =
                    (registers[Table[position + {operand_ShlInst_regIn}]] << Table[position + {operand_ShlInst_value}]) & 0xff;
                position = position + 4;
                break;
            case {opcode_ShrInst}:
                registers[Table[position + {operand_ShrInst_regOut}]] =
                    (registers[Table[position + {operand_ShrInst_regIn}]] >> Table[position + {operand_ShrInst_value}]) & 0xff;
                position = position + 4;
                break;
        }}
    }}
}}

__attribute__((visibility("default"))) int encryptVM(const unsigned char* input, unsigned char* output) {{
    unsigned char buff[17];
    buff[0] = {param_encodeVM};
    memcpy(buff + 1, input, 16);
    return runVM(buff, output);
}}

__attribute__((visibility("default"))) int getSuffix(unsigned char* output) {{
    unsigned char buff = {param_getSuffix};
    return runVM(&buff, output);
}}

#if {has_rawImplem}
const unsigned int sheduleKeySize = 13 * 16;

__attribute__((visibility("hidden"))) int sheduleKey(const unsigned char* input, unsigned char* output) {{
    unsigned char buff[17];
    buff[0] = {param_keyShedule};
    memcpy(buff + 1, input, 16);
    return runVM(buff, output);
}}

__attribute__((visibility("hidden"))) int encrypt(const unsigned char* message, const unsigned char* context, unsigned char* output) {{
    unsigned char buff[17 + sheduleKeySize];
    buff[0] = {param_encode};
    memcpy(buff + 1, message, 16);
    memcpy(buff + 17, context, sheduleKeySize);
    return runVM(buff, output);
}}

__attribute__((visibility("hidden"))) int decrypt(const unsigned char* message, const unsigned char* context, unsigned char* output) {{
    unsigned char buff[17 + sheduleKeySize];
    buff[0] = {param_decode};
    memcpy(buff + 1, message, 16);
    memcpy(buff + 17, context, sheduleKeySize);
    return runVM(buff, output);
}}


#endif
"""

        return res.format(**context)
