from io import BufferedReader
from PEInfo import PEInfo
from data import *


def readStr(file, offset):
    bytestr = b""
    bytedata = PEInfo(file, offset, 1, "little").info.to_bytes(1, "little")
    while bytedata != b'\x00':
        bytestr += bytedata
        offset += 1
        bytedata = PEInfo(file, offset, 1, "little").info.to_bytes(1, "little")
    return bytestr


def readAddr(file, offset):
    addrList = ()
    bytedata = PEInfo(file, offset, 4, "little").info.to_bytes(4, "big")

    while bytedata != b'\x00\x00\x00\x00':
        addrList += (int.from_bytes(bytedata, "big"),)
        offset += 4
        bytedata = PEInfo(file, offset, 4, "little").info.to_bytes(4, "big")
    return addrList


class ImportTableInfo:
    __OriginalFirstThunk = []
    __TimeDateStamp = ""
    __ForwarderChain = ""
    __Name1 = []
    __FirstThunk = []
    raw_data = []

    def __init__(self, file: BufferedReader, offset: int, sectionRva: int, sectionOffset: int):
        self.__OriginalFirstThunk = []
        self.__Name1 = []
        self.__FirstThunk = []
        self.raw_data = []

        for item in importtableinfo:
            print("{:25}".format(item[0]), end="")
            tmp = PEInfo(file, offset + item[1], item[2], item[3])
            tmp.PrintInfo()
            self.raw_data.append(tmp)

        self.__OriginalFirstThunk.append(self.raw_data[0].info)
        self.__TimeDateStamp = self.raw_data[1].info
        self.__ForwarderChain = self.raw_data[2].info
        self.__Name1.append(self.raw_data[3].info)
        self.__FirstThunk.append(self.raw_data[4].info)

        # 解析OriginalFirstThunk
        offset = self.__OriginalFirstThunk[0] - sectionRva + sectionOffset
        functionAddr = readAddr(file, offset)
        self.__OriginalFirstThunk.append(functionAddr)
        function = ()
        for item in functionAddr:
            if item >= 0x10000000:
                item = item % 0x10000
                function += (item,)
            else:
                realitemSN = PEInfo(file, item - sectionRva + sectionOffset, 2, "little").info
                realitem = readStr(file, item - sectionRva + sectionOffset + 2).decode()
                function += ((realitemSN, realitem),)
        self.__OriginalFirstThunk.append(function)

        # 解析Name1
        offset = self.__Name1[0] - sectionRva + sectionOffset
        bytestr = readStr(file, offset)
        self.__Name1.append(bytestr.decode())

        # 解析FirstThunk
        offset = self.__FirstThunk[0] - sectionRva + sectionOffset
        functionAddr = readAddr(file, offset)
        self.__FirstThunk.append(functionAddr)
        function = ()
        for item in functionAddr:
            if item >= 0x10000000:
                item = item % 0x10000
                function += (item,)
            else:
                realitemSN = PEInfo(file, item - sectionRva + sectionOffset, 2, "little").info
                realitem = readStr(file, item - sectionRva + sectionOffset + 2).decode()
                function += ((realitemSN, realitem),)
        self.__FirstThunk.append(function)

        functionNum = 0
        for item in self.__OriginalFirstThunk[2]:
            if type(item) == int:
                functionNum += 1
        functionName = len(self.__OriginalFirstThunk[1]) - functionNum
        print("经分析可知，此导入表指向{:}这一动态链接库，共导入了该动态链接库的{:}个函数。".format(self.__Name1[1], len(self.__OriginalFirstThunk[1])))
        print("其中以函数名方式导入的函数有{:}个，以以序号方式导入的函数有{:}个".format(functionName, functionNum))
        if len(self.__OriginalFirstThunk[2]) <= 1:
            if type(self.__OriginalFirstThunk[2][0]) == int:
                print("函数序号为：{:#06x}".format(self.__OriginalFirstThunk[2][0]))
            else:
                print("函数名为：", self.__OriginalFirstThunk[2][0][1])
        else:
            if type(self.__OriginalFirstThunk[2][0]) == int:
                print("函数序号为：{:#06x}".format(self.__OriginalFirstThunk[2][0]), end="")
                for i in range(len(self.__OriginalFirstThunk[1]) - 1):
                    if type(self.__OriginalFirstThunk[2][i + 1]) == int:
                        print(",{:#06x}".format(self.__OriginalFirstThunk[2][i + 1]))
                    else:
                        print("函数名为：", self.__OriginalFirstThunk[2][i + 1][1])
            else:
                print("函数名为：", self.__OriginalFirstThunk[2][0][1], end="")
                for i in range(len(self.__OriginalFirstThunk[1]) - 1):
                    if type(self.__OriginalFirstThunk[2][i + 1]) == int:
                        print(",{:#06x}".format(self.__OriginalFirstThunk[2][i + 1]))
                    else:
                        print(",", self.__OriginalFirstThunk[2][i + 1][1])
        if len(self.__OriginalFirstThunk[2]) <= 1:
            if type(self.__OriginalFirstThunk[2][0]) == int:
                print("导入表结构:{:} : INT {:#x} --> {:#x} --> 序号{:#06x}".format(self.__Name1[1],
                                                                             self.__OriginalFirstThunk[0],
                                                                             self.__OriginalFirstThunk[1][0],
                                                                             self.__OriginalFirstThunk[2][0]))
            else:
                print("导入表结构:{:} : INT {:#x} --> {:#x} --> 序号{:#06x},函数名{:}".format(self.__Name1[1],
                                                                                    self.__OriginalFirstThunk[0],
                                                                                    self.__OriginalFirstThunk[1][0],
                                                                                    self.__OriginalFirstThunk[2][0][0],
                                                                                    self.__OriginalFirstThunk[2][0][1]))
        else:
            if type(self.__OriginalFirstThunk[2][0]) == int:
                print("导入表结构:{:} : INT {:#x} --> {:#x} --> 序号{:#06x}".format(self.__Name1[1],
                                                                             self.__OriginalFirstThunk[0],
                                                                             self.__OriginalFirstThunk[1][0],
                                                                             self.__OriginalFirstThunk[2][0]))
                for i in range(len(self.__OriginalFirstThunk[1]) - 1):
                    if type(self.__OriginalFirstThunk[2][i + 1]) == int:
                        print(
                            ("{:^" + str(23 + len(self.__Name1[1])) + "}" + "--> {:#x} --> 序号{:#06x}").format(
                                "", self.__OriginalFirstThunk[1][i + 1],
                                self.__OriginalFirstThunk[2][i + 1]))
                    else:
                        print(("{:^" + str(23 + len(self.__Name1[1])) + "}" + "--> {:#x} --> 序号{:#06x},函数名{:}").format(
                            "",
                            self.__OriginalFirstThunk[1][i+1],
                            self.__OriginalFirstThunk[2][i + 1][0],
                            self.__OriginalFirstThunk[2][i + 1][1]))
            else:
                print("导入表结构:{:} : INT {:#x} --> {:#x} --> 序号{:#06x},函数名{:}".format(self.__Name1[1],
                                                                                    self.__OriginalFirstThunk[0],
                                                                                    self.__OriginalFirstThunk[1][0],
                                                                                    self.__OriginalFirstThunk[2][0][0],
                                                                                    self.__OriginalFirstThunk[2][0][1]))
                for i in range(len(self.__OriginalFirstThunk[1]) - 1):
                    if type(self.__OriginalFirstThunk[2][i + 1]) == int:
                        print(("{:^" + str(23 + len(self.__Name1[1])) + "}" + "--> {:#x} --> 序号{:#06x},函数名{:}").format(
                            "",
                            self.__OriginalFirstThunk[0],
                            self.__OriginalFirstThunk[1][i+1],
                            self.__OriginalFirstThunk[2][i + 1][0],
                            self.__OriginalFirstThunk[2][i + 1][1]))
                    else:
                        print(
                            ("{:^" + str(23 + len(self.__Name1[1])) + "}" + "--> {:#x} --> 序号{:#06x},函数名{:}").format(
                                "", self.__OriginalFirstThunk[1][i + 1],
                                self.__OriginalFirstThunk[2][i + 1][0],
                                self.__OriginalFirstThunk[2][i + 1][1]))
