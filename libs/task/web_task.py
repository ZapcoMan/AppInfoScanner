#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner
import os
import config
import hashlib
from queue import Queue


class WebTask(object):
    thread_list = []
    value_list = []
    result_dict = {}

    def __init__(self, path):
        self.path = path
        self.file_queue = Queue()
        self.file_identifier = []
        self.permissions = []

    def start(self):
        """
        根据配置和路径初始化扫描参数。

        此方法首先检查配置中的网页文件后缀列表是否为空。如果为空，则使用默认的后缀列表。
        如果指定路径是目录，则递归扫描该目录下的文件。如果路径是文件，检查其后缀是否在后缀列表中。
        如果文件后缀不在列表中，抛出异常；否则，将文件路径加入待处理队列。

        Returns:
            dict: 包含扫描参数的字典，如组件列表、是否包含shell脚本标志、文件队列等。
        """
        # 检查配置中的网页文件后缀列表是否为空
        if len(config.web_file_suffix) <= 0:
            scanner_file_suffix = ["html", "js", "html", "xml"]
        else:
            scanner_file_suffix = config.web_file_suffix

        # 判断路径是否为目录
        if os.path.isdir(self.path):
            # 如果是目录，则调用私有方法扫描目录下的文件
            self.__get_scanner_file__(self.path, scanner_file_suffix)
        else:
            # 如果不是目录，检查文件后缀是否在后缀列表中
            if not (self.path.split(".")[-1] in scanner_file_suffix):
                # 如果文件后缀不在列表中，构造错误信息并抛出异常
                err_info = ("Retrieval of this file type is not supported. Select a file or directory with a suffix of %s" % ",".join(scanner_file_suffix))
                raise Exception(err_info)
            # 将符合条件的文件路径加入文件队列
            self.file_queue.put(self.path)

        # 返回包含扫描参数的字典
        return {"comp_list": [], "shell_flag": False, "file_queue": self.file_queue, "packagename": None, "file_identifier": self.file_identifier, "permissions": self.permissions}

    def __get_scanner_file__(self, scanner_dir, file_suffix):
        """
        递归扫描指定目录下的所有文件，特别是处理特定后缀的文件。

        :param scanner_dir: 需要扫描的目录路径
        :param file_suffix: 关注的文件后缀名列表
        """
        # 获取目录下的所有文件和子目录
        dir_or_files = os.listdir(scanner_dir)
        for dir_file in dir_or_files:
            # 构造完整的文件或目录路径
            dir_file_path = os.path.join(scanner_dir, dir_file)
            # 如果是目录，则递归调用自身
            if os.path.isdir(dir_file_path):
                self.__get_scanner_file__(dir_file_path, file_suffix)
            else:
                # 如果文件有后缀名
                if len(dir_file.split(".")) > 1:
                    # 如果文件后缀名在关注的后缀名列表中
                    if dir_file.split(".")[-1] in file_suffix:
                        # 打开文件，计算并获取MD5值
                        with open(dir_file_path,'rb') as f:
                            dex_md5 = str(hashlib.md5().update(f.read()).hexdigest()).upper()
                            self.file_identifier.append(dex_md5)
                        # 将文件路径放入队列中
                        self.file_queue.put(dir_file_path)