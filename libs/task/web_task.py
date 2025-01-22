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
        if len(config.web_file_suffix) <= 0:
            scanner_file_suffix = ["html", "js", "html", "xml"]

        scanner_file_suffix = config.web_file_suffix
        if os.path.isdir(self.path):
            self.__get_scanner_file__(self.path, scanner_file_suffix)
        else:
            if not (self.path.split(".")[-1] in scanner_file_suffix):
                err_info = ("Retrieval of this file type is not supported. Select a file or directory with a suffix of %s" % ",".join(scanner_file_suffix))
                raise Exception(err_info)
            self.file_queue.put(self.path)
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