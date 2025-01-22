#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner
import sys
import config
import requests
import threading
import libs.core as cores
from requests.packages import urllib3
from requests.adapters import HTTPAdapter


class DownloadThreads(threading.Thread):

    def __init__(self, input_path, file_name, cache_path, types):
        threading.Thread.__init__(self)
        self.url = input_path
        self.types = types
        self.cache_path = cache_path
        self.file_name = file_name

    def __requset__(self):
        """
        发起HTTP/HTTPS请求并处理响应。

        该方法根据config中的配置信息发起POST或GET请求，下载文件或获取HTML内容，并保存到缓存路径。
        对于HTTP和HTTPS请求，设置最大重试次数以提高请求成功的概率。此外，针对不同的操作系统类型，
        采取不同的处理方式：对于'Android'或'iOS'，以二进制形式下载文件并显示下载进度；对于其他情况，
        则直接保存响应的HTML文本。

        Raises:
            Exception: 如果请求过程中发生任何异常，均抛出异常。
        """
        try:
            # 创建一个Session对象，以保持会话状态
            session = requests.Session()
            # 为HTTP和HTTPS请求分别添加重试适配器，以提高请求的容错性
            session.mount('http://', HTTPAdapter(max_retries=3))
            session.mount('https://', HTTPAdapter(max_retries=3))
            # 禁用keep-alive，以避免长连接带来的潜在问题
            session.keep_alive = False
            # 设置默认的重试次数，以应对网络问题
            session.adapters.DEFAULT_RETRIES = 5
            # 禁用urllib3的警告，减少不必要的日志输出
            urllib3.disable_warnings()

            # 根据配置中的请求方法，发起POST或GET请求
            if config.method.upper() == "POST":
                resp = session.post(url=self.url, params=config.data, headers=config.headers, timeout=30)
            else:
                resp = session.get(url=self.url, data=config.data, headers=config.headers, timeout=30)

            # 检查响应状态码，确保请求成功
            if resp.status_code == requests.codes.ok:
                # 根据操作系统类型，处理响应内容
                if self.types == "Android" or self.types == "iOS":
                    # 下载文件并显示下载进度
                    count = 0
                    progress_tmp = 0
                    length = float(resp.headers['content-length'])
                    with open(self.cache_path, "wb") as f:
                        for chunk in resp.iter_content(chunk_size=512):
                            if chunk:
                                f.write(chunk)
                                count += len(chunk)
                                progress = int(count / length * 100)
                                if progress != progress_tmp:
                                    progress_tmp = progress
                                    print("\r", end="")
                                    print("[*] Download progress: {}%: ".format(progress), "▋" * (progress // 2), end="")
                                    sys.stdout.flush()
                            f.close()
                else:
                    # 直接保存HTML文本
                    html = resp.text
                    with open(self.cache_path, "w", encoding='utf-8', errors='ignore') as f:
                        f.write(html)
                        f.close()
                # 设置下载标志为True，表示下载成功
                cores.download_flag = True
        except Exception as e:
            # 捕获并抛出异常，便于上层调用者处理
            raise Exception(e)

    def run(self):
        threadLock = threading.Lock()
        self.__requset__()
