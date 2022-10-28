import json
import pprint
from colorama import Fore
from pathlib import Path
from datetime import datetime, timedelta


class Color:
    @staticmethod
    def print_focus(data: str):
        print(Fore.YELLOW+data+Fore.RESET)

    @staticmethod
    def print_success(data: str):
        print(Fore.LIGHTGREEN_EX+data+Fore.RESET)

    @staticmethod
    def print_failed(data: str):
        print(Fore.LIGHTRED_EX+data+Fore.RESET)

    @staticmethod
    def print(data):
        pprint.pprint(data)


class Db:
    def __init__(self, db_path: Path, hours: int):
        self.db_path = db_path
        self.hours = hours      # 保留时间

    def get_files(self):
        """获取文件列表"""
        return sorted([i for i in self.db_path.iterdir() if i.suffix == '.json'])

    def get_filenames(self):
        """获取文件名列表"""
        return sorted([i.stem for i in self.get_files()])

    def find_new(self, data: list):
        """寻找新漏洞"""
        old_cves = []
        for file in self.get_files():
            with open(file) as f:
                old_data = json.load(f)['data']
            for i in old_data:
                if i['cve'] not in old_cves:
                    old_cves.append(i['cve'])

        return [i for i in data if i['cve'] not in old_cves]

    def add_file(self, filename: str, data: dict):
        """创建文件"""
        with open(self.db_path.joinpath(f'{filename}.json'), 'w+') as f:
            json.dump(data, f, indent=4)

    def cleanup(self):
        """清理超出保留时间的文件"""
        files = self.get_files()
        end = datetime.strptime(files[-1].stem, "%Y-%m-%d %H:%M:%S")
        for file in files:
            if end - datetime.strptime(file.stem, "%Y-%m-%d %H:%M:%S") > timedelta(hours=self.hours):
                file.unlink(missing_ok=True)
