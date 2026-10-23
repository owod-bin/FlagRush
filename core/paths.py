# -*- coding: utf-8 -*-
"""
路径解析 —— 同时兼容「源码运行」和「PyInstaller 打包后的 exe」
================================================================
两种模式的区别：
  源码运行：  一切都在 一把梭工具/ 下面
  打包成 exe： 代码和数据被收进 _internal/，但 tools/、flag格式.txt、
               工作区/、uploads/ 这些**用户可见可改的东西必须在 exe 旁边**

所以分两个概念：
  res_dir()  —— 只读资源（core 模块、webui.html、内置数据），打包后在 _internal 里
  app_dir()  —— exe 所在目录（外部工具、配置文件、输出），打包后在 exe 旁边
"""
import os
import sys


def is_frozen():
    """是不是打包后的 exe"""
    return bool(getattr(sys, "frozen", False))


def res_dir():
    """只读资源目录"""
    if is_frozen():
        return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(sys.executable)))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def app_dir():
    """exe / 工具根目录 —— 可写，也是 tools/ 和配置文件所在位置"""
    if is_frozen():
        return os.path.dirname(os.path.abspath(sys.executable))
    return res_dir()


def tool_path(*parts):
    """tools/ 下的某个文件"""
    return os.path.join(app_dir(), "tools", *parts)


def data_path(name):
    """根目录下的文件（flag格式.txt / 工作区 / uploads …）"""
    return os.path.join(app_dir(), name)


def ensure_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        pass
    return path
