import json
from xmlrpc.client import Boolean
import requests

from utils import Color


class feishuBot:
    """飞书群机器人
    https://open.feishu.cn/document/ukTMukTMukTM/ucTM5YjL3ETO24yNxkjN
    """

    def __init__(self, key, proxy_url='') -> None:
        self.key = key
        self.proxy = {'http': proxy_url, 'https': proxy_url} if proxy_url else {'http': None, 'https': None}

    def make_card(self, hit: bool, cve: dict):
        vendor = product = None
        if vendors := cve['vendors']:
            vendor = vendors[0]['vendor']
            product = vendors[0]['products'][0]['product']

        publishedDate = cve['publishedDate'][:10] if cve['publishedDate'] else None
        lastModifiedDate = cve['lastModifiedDate'][:10] if cve['lastModifiedDate'] else None
        epss_score = '{:.2%}'.format(float(cve['epss_score'] or 0))
        vendor_advisories = cve['vendor_advisories'][0] if cve['vendor_advisories'] else None
        github = '\n'.join([i['url'] for i in cve['github_repos']])
        reddit = '\n'.join([i['reddit_url'] for i in cve['reddit_posts']])
        twitter = '\n'.join([f'https://twitter.com/{i["twitter_user_handle"]}/status/{i["tweet_id"]}' for i in cve['tweets']])

        card = {
            'header': {
                'template': 'red' if hit else 'orange',
                'title': {
                    'content': f'【漏洞情报】{cve["cve"]} | {vendor} - {product}',
                    'tag': 'plain_text'
                }
            },
            'elements': [
                {
                    'tag': 'div',
                    'fields': [
                        {
                            'is_short': True,
                            'text': {
                                'content': f'**漏洞时间**\n公开：{publishedDate}\n更新：{lastModifiedDate}',
                                'tag': 'lark_md'
                            }
                        },
                        {
                            'is_short': True,
                            'text': {
                                'content': f'**漏洞等级**\nCVSS：{cve["severity"]}\nEPSS：{epss_score}',
                                'tag': 'lark_md'
                            }
                        }
                    ]
                },
                {
                    'tag': 'div',
                    'text': {
                        'content': f'**漏洞公告**\nhttps://nvd.nist.gov/vuln/detail/{cve["cve"]}\n{vendor_advisories}',
                        'tag': 'lark_md'
                    }
                },
                {
                    'tag': 'div',
                    'text': {
                        'content': f'**漏洞概要**\n{cve["description"]}',
                        'tag': 'lark_md'
                    }
                },
                {
                    'tag': 'div',
                    'text': {
                        'content': f'**GitHub**\n{github}',
                        'tag': 'lark_md'
                    }
                },
                {
                    'tag': 'div',
                    'text': {
                        'content': f'**Reddit**\n{reddit}',
                        'tag': 'lark_md'
                    }
                },
                {
                    'tag': 'div',
                    'text': {
                        'content': f'**Twitter**\n{twitter}',
                        'tag': 'lark_md'
                    }
                }
            ]
        }
        return card

    def send(self, cves: list):
        for cve in cves:
            data = {'msg_type': 'interactive', 'card': self.make_card(cve[0], cve[1])}
            headers = {'Content-Type': 'application/json'}
            url = f'https://open.feishu.cn/open-apis/bot/v2/hook/{self.key}'
            r = requests.post(url=url, headers=headers, data=json.dumps(data), proxies=self.proxy)

            if r.status_code == 200:
                Color.print_success(f'[+] feishuBot 发送成功 {cve[1]["cve"]}')
            else:
                Color.print_failed(f'[-] feishuBot 发送失败 {cve[1]["cve"]}')
                print(r.text)
