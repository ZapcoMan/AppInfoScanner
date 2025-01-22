#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner
import re
import time
import threading
import requests
import libs.core as cores

class NetThreads(threading.Thread):

    def __init__(self, threadID, name, domain_queue, worksheet):
        threading.Thread.__init__(self)
        self.name = name
        self.threadID = threadID
        self.lock = threading.Lock()
        self.domain_queue = domain_queue
        self.worksheet = worksheet

    def __get_Http_info__(self, threadLock):
        """
        获取HTTP信息并更新Excel工作表。

        从域名队列中获取域名和URL IP，然后请求URL的信息。
        如果请求成功且结果不为错误，则将信息写入Excel工作表中。

        参数:
        - threadLock: 线程锁，用于同步对共享资源的访问。

        返回值:
        无
        """
        while True:
            # 检查域名队列是否为空，如果为空则退出循环
            if self.domain_queue.empty():
                break

            # 从队列中获取域名信息，包括域名和URL IP
            domains = self.domain_queue.get(timeout=5)
            domain = domains["domain"]
            url_ip = domains["url_ip"]

            # 短暂休眠，以模拟处理时间或减轻目标服务器的负担
            time.sleep(2)

            # 发起HTTP请求并获取结果
            result = self.__get_request_result__(url_ip)
            print("[+] Processing URL address："+url_ip)

            # 如果结果不为错误，则尝试获取线程锁以更新Excel工作表
            # 检查结果是否为错误
            if result != "error":
                # 尝试获取线程锁，以便安全地写入Excel
                if self.lock.acquire(True):
                    # 更新Excel行号并写入域名、URL IP等信息
                    cores.excel_row = cores.excel_row + 1
                    self.worksheet.cell(row=cores.excel_row, column=1, value=cores.excel_row-1)
                    self.worksheet.cell(row=cores.excel_row, column=2, value=url_ip)
                    self.worksheet.cell(row=cores.excel_row, column=3, value=domain)

                    # 如果结果不是超时，则写入更多详细信息
                    if result != "timeout":
                        self.worksheet.cell(row=cores.excel_row, column=4, value=result["status"])
                        self.worksheet.cell(row=cores.excel_row, column=5, value=result["des_ip"])
                        self.worksheet.cell(row=cores.excel_row, column=6, value=result["server"])
                        self.worksheet.cell(row=cores.excel_row, column=7, value=result["title"])
                        self.worksheet.cell(row=cores.excel_row, column=8, value=result["cdn"])

                    # 释放线程锁，允许其他线程进行写入操作
                    self.lock.release()

    class SomeClass:
        """
        一个示例类，用于演示如何添加注释。
        """

        def __get_request_result__(self, url):
            """
            发送GET请求并获取结果。

            此函数通过requests库发送GET请求，并解析响应头和内容，提取相关信息，如服务器类型、Cookie、CDN信息、目标IP和源IP以及页面标题。

            参数:
            url (str): 目标URL地址。

            返回:
            dict: 包含请求状态、服务器信息、CDN信息、目标IP、源IP和页面标题的字典。
            如果URL无效或请求失败，则返回"error"或"timeout"。
            """
            # 初始化结果字典，用于存储请求结果和解析出的信息
            result = {"status": "", "server": "", "cookie": "",
                      "cdn": "", "des_ip": "", "sou_ip": "", "title": ""}
            # 初始化CDN信息字符串
            cdn = ""
            try:
                # 发送GET请求，设置超时时间和流式响应
                with requests.get(url, timeout=5, stream=True) as rsp:
                    # 获取并记录HTTP状态码
                    status_code = rsp.status_code
                    result["status"] = status_code
                    # 获取响应头
                    headers = rsp.headers
                    # 检查并记录服务器类型
                    if "Server" in headers:
                        result["server"] = headers['Server']
                    # 检查并记录Cookie信息
                    if "Cookie" in headers:
                        result["cookie"] = headers['Cookie']
                    # 检查并累加CDN信息
                    if "X-Via" in headers:
                        cdn = cdn + headers['X-Via']
                    if "Via" in headers:
                        cdn = cdn + headers['Via']
                    result["cdn"] = cdn
                    # 获取底层socket对象
                    sock = rsp.raw._connection.sock
                    # 如果socket对象存在，获取目标IP和源IP信息
                    if sock:
                        des_ip = sock.getpeername()[0]
                        sou_ip = sock.getsockname()[0]
                        if des_ip:
                            result["des_ip"] = des_ip
                        if sou_ip:
                            result["sou_ip"] = sou_ip
                        # 关闭socket连接
                        sock.close()
                    # 获取页面内容
                    html = rsp.text
                    # 使用正则表达式提取页面标题
                    title = re.findall('<title>(.+)</title>', html)
                    if title:
                        result["title"] = title[0]
                    # 关闭响应
                    rsp.close()
                    # 返回结果字典
                    return result
            # 异常处理：无效URL
            except requests.exceptions.InvalidURL as e:
                return "error"
            # 异常处理：连接错误或读取超时
            except requests.exceptions.ConnectionError as e1:
                return "timeout"
            except requests.exceptions.ReadTimeout as e2:
                return "timeout"

    def run(self):
        threadLock = threading.Lock()
        self.__get_Http_info__(threadLock)
