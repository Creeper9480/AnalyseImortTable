import time

from ImportTableInfo import ImportTableInfo
from PEInfo import PEInfo
from data import *
import sys
from operator import add
from functools import reduce


def analyseDos():
    print("\nPE文件头位于文件偏移{:#010x}处".format(pedata["e_lfanew字段"].info))


def analysePE():
    print("\n根据Machine字段和SizeofOptionalHeader字段，", end="")
    if pedata["Machine字段"].info == 0x014c and pedata["SizeofOptionalHeader字段"].info == 0xe0 and pedata[
        "Magic字段"].info == 0x10b:
        print("该PE文件为32位PE文件")
    elif pedata["Machine字段"].info == 0x8664 and pedata["SizeofOptionalHeader字段"].info == 0xf0 and pedata[
        "Magic字段"].info == 0x20b:
        print("该PE文件为64位PE文件")
    # 转换时间戳
    timeStamp = float(pedata["TimedateStamp字段"].info)
    timeArray = time.localtime(timeStamp)
    print(
        "该PE文件一共有{:}个节，创建自{:}".format(pedata["NumberofSections字段"].info, time.strftime("%Y-%m-%d %H:%M:%S", timeArray)))
    print("该PE文件的优先装入地址为{:#x}".format(pedata["ImageBase字段"].info))
    print("该PE文件在内存中的区块的对齐大小为{:#x}，在文件中的区块的对齐大小为{:#x}".format(pedata["SectionAlignment字段"].info,
                                                              pedata["FileAlignment字段"].info))
    print("该PE文件在内存中所占大小为{:#x}".format(pedata["SizeOfImage字段"].info))
    print("该PE文件对齐后所有头部信息以及节表大小之和为{:#x}".format(pedata["SizeOfHeaders字段"].info))
    if pedata["DataDirectory_Export_Size"].info == 0:
        print("该PE文件不存在导出表!")
    else:
        print("该PE文件的导出表的起始RVA为{:}，大小为{:}".format(pedata["DataDirectory_Export_Rva"].info,
                                                  pedata["DataDirectory_Export_Size"].info))
    if pedata["DataDirectory_Import_Size"].info == 0:
        print("该PE文件不存在导入表!")
    else:
        print("该PE文件的导入表的起始RVA为{:#x}，大小为{:#x}".format(pedata["DataDirectory_Import_Rva"].info,
                                                      pedata["DataDirectory_Import_Size"].info))


def analyseSection():
    print("\n该PE文件一共有{:}个节".format(pedata["NumberofSections字段"].info))
    rvaList = []
    for item in sectiondata:
        rvaList.append(sectiondata[item][2].info)
        print("{:10}的真实大小为{:#x}，起始Rva为{:#x}，在文件中的偏移为{:#x}".format(item, sectiondata[item][1].info,
                                                                  sectiondata[item][2].info, sectiondata[item][4].info))
    for item in sectiondata:
        if sectiondata[item][2].info == min(rvaList, key=lambda x: abs(x - pedata["DataDirectory_Import_Rva"].info)):
            offset = sectiondata[item][4].info + pedata["DataDirectory_Import_Rva"].info - sectiondata[item][2].info
            print("导入表的起始Rva为{:#x}，{:}的起始Rva为{:#x}，故导入表位于{:}中\n由于{:}在文件中的偏移为{:#x}，故导入表在文件中的偏移为{:#x}".format(
                pedata["DataDirectory_Import_Rva"].info, item, sectiondata[item][2].info, item, item,
                sectiondata[item][4].info, offset))
            break
    return item


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        file = open(sys.argv[1], "rb")
        print(file.read())
    else:
        file = open("hello25 - 20192426.exe", "rb")
        # file = open("hello25 - 201924262.exe", "rb")
    print("{:=^55}\n".format("PE文件DOS头部分"))
    for item in dosinfo:
        print("{:25}".format(item[0]), end="")
        tmp = PEInfo(file, item[1], item[2], item[3])
        tmp.PrintInfo()
        pedata[item[0]] = tmp
    analyseDos()

    print("\n{:=^55}\n".format("PE文件头部分"))
    for item in peinfo:
        print("{:25}".format(item[0]), end="")
        tmp = PEInfo(file, pedata["e_lfanew字段"].info + item[1], item[2], item[3])
        tmp.PrintInfo()
        pedata[item[0]] = tmp
    analysePE()

    print("\n{:=^55}".format("PE文件节表部分"))
    for sectionNumber in range(pedata["NumberofSections字段"].info):
        print()
        sectiontuple = ()
        for item in sectioninfo:
            print("{:25}".format(item[0]), end="")
            tmp = PEInfo(file, pedata["e_lfanew字段"].info + 0x28 * sectionNumber + item[1], item[2], item[3])
            tmp.PrintInfo()
            sectiontuple += (tmp,)
        sectiondata[sectiontuple[0].info.strip("\0")] = sectiontuple

    sectionName = analyseSection()

    print("\n{:=^55}".format("PE文件导入表部分"))
    offset = sectiondata[sectionName][4].info + pedata["DataDirectory_Import_Rva"].info - sectiondata[sectionName][
        2].info
    size = pedata["DataDirectory_Import_Size"].info
    numberOfImportTable = int(size / 0x14) - 1
    for i in range(numberOfImportTable):
        print()
        print("第{:}个导入表".format(i + 1))
        importtable = ImportTableInfo(file, offset + i * 0x14, sectiondata[sectionName][2].info,
                                      sectiondata[sectionName][4].info)
        importtables[i] = importtable
