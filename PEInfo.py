from io import BufferedReader


class PEInfo:
    __baseaddr = 0
    __size = 0
    __byteorder = ""
    __raw_data = b""
    __data = b""
    __datastr = "0x"
    info = ""

    def __init__(self, file: BufferedReader, offset: int, size: int, byteorder: str = "little"):
        """
        找到文件中对应的位置并读取相应大小的数据，
        :param file: 文件
        :param offset: 文件的偏移
        :param size: 读取的大小（字节）
        :param byteorder: 字节序，默认为小端字节序，请从{[“little”,“l”]|[“big”,“b”]}中进行参数选择
        :return: 读取到的数据内容
        """
        file.seek(offset)
        self.__size = size
        self.__baseaddr = file.tell()
        self.__raw_data = file.read(size)
        self.__byteorder = byteorder
        if byteorder in ['little', 'l']:

            for i in range(size):
                self.__data += self.__raw_data[size - 1 - i].to_bytes(1, "big")
            self.__datastr += self.__data.hex()

            self.info = int.from_bytes(self.__raw_data, byteorder='little')
        elif byteorder in ['big', 'b']:
            self.info = self.__raw_data.decode('utf-8', 'ignore')

    def PrintInfo(self):
        if self.__byteorder in ['little', 'l']:
            if self.__size == 2:
                print("\t{0:^#010x}\t\t\t{1:10}".format(self.__baseaddr, self.__datastr))
            elif self.__size == 4:
                print("\t{0:#010x}\t\t\t{1:10}".format(self.__baseaddr, self.__datastr))
        elif self.__byteorder in ['big', 'b']:
            print("\t{0:#010x}\t\t\t{1:}".format(self.__baseaddr, self.__raw_data.decode('utf-8', 'ignore').strip("\0")))
