#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner
import os
import re
import shutil
import zipfile
import binascii
import platform
import libs.core as cores
from queue import Queue


class iOSTask(object):
    elf_file_name = ""

    def __init__(self, path):
        self.path = path
        self.file_queue = Queue()
        self.shell_flag = False
        self.file_identifier = []
        self.permissions = []

    def start(self):
        """
        启动文件处理流程。

        本函数根据文件类型（ipa或Mach-o）来执行相应的处理流程。
        它首先检查文件扩展名，然后根据文件内容或类型进行解码或扫描。

        Returns:
            dict: 包含处理结果的字典，包括shell_flag、file_queue等信息。
        """
        # 获取文件路径
        file_path = self.path

        # 判断文件是否为ipa文件
        if file_path.split(".")[-1] == 'ipa':
            # 对ipa文件进行解码
            self.__decode_ipa__(cores.output_path)
            # 扫描解码后的ipa文件
            self.__scanner_file_by_ipa__(cores.output_path)
        else:
            # 判断文件是否为Mach-o文件
            if self.__get_file_header__(file_path):
                # 将文件路径放入文件队列中
                self.file_queue.put(file_path)
            else:
                # 抛出异常，提示不支持的文件类型
                raise Exception(
                    "Retrieval of this file type is not supported. Select IPA file or Mach-o file.")

        # 返回包含处理结果的字典
        return {"shell_flag": self.shell_flag, "file_queue": self.file_queue, "comp_list": [], "packagename": None, "file_identifier": self.file_identifier, "permissions": self.permissions}
    def __get_file_header__(self, file_path):
        """
        获取文件头信息并判断是否为Mach-O文件。

        参数:
        file_path (str): 文件路径。

        返回:
        bool: 如果文件是Mach-O格式，则返回True，否则返回False。
        """
        # 初始化文件头位置指针
        hex_hand = 0x0

        # 提取文件名作为文件标识符
        macho_name = os.path.split(file_path)[-1]
        self.file_identifier.append(macho_name)

        # 打开二进制文件以读取文件头信息
        with open(file_path, "rb") as macho_file:
            # 移动文件读取指针到文件头
            macho_file.seek(hex_hand, 0)

            # 读取并转换文件头4字节为十六进制表示
            magic = binascii.hexlify(macho_file.read(4)).decode().upper()

            # 定义Mach-O文件的魔数列表
            macho_magics = ["CFFAEDFE", "CEFAEDFE", "BEBAFECA", "CAFEBABE"]

            # 检查文件头魔数是否匹配Mach-O文件格式
            if magic in macho_magics:
                # 如果是Mach-O文件，调用私有方法进行进一步处理
                self.__shell_test__(macho_file, hex_hand)

                # 关闭文件并返回True表示处理成功
                macho_file.close()
                return True

            # 如果不是Mach-O文件，关闭文件并返回False
            macho_file.close()
            return False

    def __shell_test__(self, macho_file, hex_hand):
        """
        检测给定的macho文件是否包含特定的加密信息，以判断是否具有特定的shell功能。

        参数:
        - macho_file: 文件对象，指向待检测的macho文件。
        - hex_hand: int，文件内部的初始读取位置指针。

        该方法通过读取和解析macho文件的特定部分，判断文件是否具有特定的加密标识，
        从而确定文件是否包含shell功能。这一过程涉及对文件的二进制内容进行解析，并根据
        解析结果更新类实例的属性。
        """
        while True:
            # 读取文件的前4字节并将其转换为十六进制字符串，用于判断文件类型
            magic = binascii.hexlify(macho_file.read(4)).decode().upper()
            if magic == "2C000000":
                # 当文件类型匹配时，重置文件读取位置到指定的加密信息位置
                macho_file.seek(hex_hand, 0)
                # 读取并转换加密信息命令的24字节到十六进制字符串
                encryption_info_command = binascii.hexlify(
                    macho_file.read(24)).decode()
                # 提取加密信息命令的最后8个字符，用于判断加密标识
                cryptid = encryption_info_command[-8:len(
                    encryption_info_command)]
                if cryptid == "01000000":
                    # 当加密标识匹配时，设置shell标志为True，表示文件包含shell功能
                    self.shell_flag = True
                break
            # 如果当前文件类型不匹配，移动文件读取位置指针，继续搜索
            hex_hand = hex_hand + 4

    def __scanner_file_by_ipa__(self, output):
        """
        根据IPA文件扫描特定后缀的文件。

        本函数关注于从IPA文件解压后的输出目录中，扫描特定后缀的文件。
        这些文件可能包含敏感信息或需要进一步处理。

        参数:
        - output: 解压IPA文件后的输出目录路径。

        返回:
        无直接返回值。但通过调用`self.__get_scanner_file__`函数处理扫描结果。
        """
        # 定义需要扫描的文件后缀列表，这些文件类型可能包含需要分析的内容
        scanner_file_suffix = ["plist", "js", "xml", "html"]

        # 构造扫描目录路径，"Payload"是IPA解压后包含应用数据的目录
        scanner_dir = os.path.join(output, "Payload")

        # 调用内部函数处理具体的文件扫描逻辑
        self.__get_scanner_file__(scanner_dir, scanner_file_suffix)

    def __get_scanner_file__(self, scanner_dir, file_suffix):
        """
        递归获取指定目录下的特定后缀文件。

        :param scanner_dir: 需要扫描的目录路径
        :param file_suffix: 需要获取的文件后缀名列表
        """
        # 获取目录下的所有文件和子目录
        dir_or_files = os.listdir(scanner_dir)
        for dir_file in dir_or_files:
            # 构造完整的文件或目录路径
            dir_file_path = os.path.join(scanner_dir, dir_file)
            # 如果是目录，则递归调用自身
            if os.path.isdir(dir_file_path):
                # 如果目录名以.app结尾，提取 ELF 文件名
                if dir_file.endswith(".app"):
                    self.elf_file_name = dir_file.replace(".app", "")
                self.__get_scanner_file__(dir_file_path, file_suffix)
            else:
                # 如果文件名与ELF文件名相同，获取文件头信息并加入处理队列
                if self.elf_file_name == dir_file:
                    self.__get_file_header__(dir_file_path)
                    self.file_queue.put(dir_file_path)
                    continue
                # 如果资源标志为真，对文件后缀进行处理
                if cores.resource_flag:
                    dir_file_suffix = dir_file.split(".")
                    # 对有后缀的文件进行判断
                    if len(dir_file_suffix) > 1:
                        # 如果文件后缀在指定的后缀列表中，获取文件头信息并加入处理队列
                        if dir_file_suffix[-1] in file_suffix:
                            self.__get_file_header__(dir_file_path)
                            self.file_queue.put(dir_file_path)

    def __decode_ipa__(self, output_path):
        with zipfile.ZipFile(self.path, "r") as zip_files:
            zip_file_names = zip_files.namelist()
            zip_files.extract(zip_file_names[0], output_path)
            try:
                new_zip_file = zip_file_names[0].encode(
                    'cp437').decode('utf-8')
            except UnicodeEncodeError:
                new_zip_file = zip_file_names[0].encode(
                    'utf-8').decode('utf-8')

                old_zip_dir = self.__get_parse_dir__(
                    output_path, zip_file_names[0])
                new_zip_dir = self.__get_parse_dir__(output_path, new_zip_file)
                os.rename(old_zip_dir, new_zip_dir)

            for zip_file in zip_file_names:
                old_ext_path = zip_files.extract(zip_file, output_path)
                if not "Payload" in old_ext_path:
                    continue
                start = str(old_ext_path).index("Payload")
                dir_path = old_ext_path[start:len(old_ext_path)]
                old_ext_path = os.path.join(output_path, dir_path)
                try:
                    new_zip_file = zip_file.encode('cp437').decode('utf-8')
                except UnicodeEncodeError:
                    new_zip_file = zip_file.encode('utf-8').decode('utf-8')

                new_ext_path = os.path.join(output_path, new_zip_file)

                if platform.system() == "Windows":
                    new_ext_path = new_ext_path.replace("/", "\\")

                if not os.path.exists(new_ext_path):
                    dir_path = os.path.dirname(new_ext_path)
                    if not os.path.exists(dir_path):
                        os.makedirs(dir_path)
                shutil.move(old_ext_path, new_ext_path)
                # 当旧目录与新目录不一致时，删除旧的目录
                if not (old_ext_path == new_ext_path) and os.path.exists(old_ext_path) and (".app" in old_ext_path):
                    try:
                        # mac发生权限问题的时候做处理
                        os.remove(old_ext_path)
                    except Exception:
                        shutil.rmtree(old_ext_path)

    def __get_parse_dir__(self, output_path, file_path):
        """
        根据给定的文件路径和输出路径，获取解析后的目录路径。

        该方法首先定位到文件路径中的 "Payload/" 目录和 ".app" 后缀的位置，
        然后根据操作系统对路径进行相应的处理，最后拼接输出路径和处理后的路径，
        返回解析后的目录路径。

        参数:
        output_path (str): 解析结果的输出路径。
        file_path (str): 需要解析的文件的路径。

        返回:
        str: 解析后的目录路径。
        """
        # 定位到 "Payload/" 目录的起始位置
        start = file_path.index("Payload/")
        # 定位到 ".app" 后缀的结束位置
        end = file_path.index(".app")
        # 提取根目录路径
        root_dir = file_path[start:end]
        # 如果是 Windows 系统，则将路径中的斜杠替换为反斜杠
        if platform.system() == "Windows":
            root_dir = root_dir.replace("/", "\\")
        # 拼接输出路径和处理后的根目录路径
        old_root_dir = os.path.join(output_path, root_dir + ".app")
        # 返回解析后的目录路径
        return old_root_dir
