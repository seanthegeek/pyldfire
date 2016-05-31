# -*- coding: utf-8 -*-
"""A Python module for Palo Alto Network's WildFire API

Copyright 2016 Sean Whalen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from io import StringIO

from requests import Session
import xmltodict

__author__ = 'Sean Whalen'
__version__ = '7.1'


def list_to_file(l):
    return StringIO('\n'.join(l))


class WildFireException(Exception):
    pass


class WildFire(object):
    errors = {
        401: "API key invalid",
        403: "Permission denied",
        404: "Not found",
        405: "Method other than POST used",
        413: "Sample file size over max limit",
        418: "Sample file type is not supported",
        419: "Max calls per day reached",
        421: "Invalid hash value",
        500: "Internal WildFire error",
        513: "File upload failed"
    }

    verdicts = {
        0: "Benign",
        1: "Malware",
        2: "Greyware",
        -100: "Pending",
        -101: "Error",
        -102: "Not found"
    }

    @staticmethod
    def raise_errors(response, *args, **kwargs):
        if response.headers['content-type'].lower() == "text/xml":
            results = xmltodict.parse(response.text)
            if "error" in results.keys():
                raise WildFireException(results["error"]["error-message"])
        if response.status_code != 200:
            raise WildFireException(WildFire.errors[response.status_code])

    def __init__(self, api_key, host=None, api_root=None):
        if host is None:
            self.host = "wildfire.paloaltonetworks.com"
        else:
            self.host = host
        if api_root is None:
            self.root = "https://{0}/publicapi".format(self.host)
        else:
            self.root = "https://{0}/{1}".format(self.host, api_root)
        self.key = api_key
        
        self.session = Session()
        self.session.hooks = dict(response=WildFire.raise_errors)
        self.session.headers.update({"User-Agent": "pyldfire/{0}".format(__version__)})

    def get_verdict(self, file_hashes):
        multi = False
        if type(file_hashes) == list:
            if len(file_hashes) == 1:
                file_hashes = file_hashes[0]
            elif len(file_hashes) > 1:
                multi = True
        if multi:
            request_url = "{0}{1}".format(self.root, "/get/verdicts")
            hash_file = list_to_file(file_hashes)
            files = dict(file=("hashes", hash_file))
            data = dict(apikey=self.key)
            response = self.session.post(request_url, data=data, files=files)
            results = xmltodict.parse(response.text)['wildfire']['get-verdict-info']
            for i in range(len(results)):
                results[i]["verdict"] = WildFire.verdicts[int(results[i]["verdict"])]
        else:
            request_url = "{0}{1}".format(self.root, "/get/verdict")
            data = dict(apikey=self.key, hash=file_hashes)
            response = self.session.post(request_url, data=data)
            verdict = int(xmltodict.parse(response.text)['wildfire']['get-verdict-info']['verdict'])
            results = WildFire.verdicts[verdict]

        return results

    def submit_file(self, file_obj, filename="sample"):
        url = "{0}{1}".format(self.root, "/submit/file")
        data = dict(apikey=self.key)
        files = dict(file=(filename, file_obj))
        response = self.session.post(url, data=data, files=files)

        return xmltodict.parse(response.text)['wildfire']['upload-file-info']

    def submit_remote_file(self, url):
        request_url = "{0}{1}".format(self.root, "/submit/url")
        data = dict(apikey=self.key, url=url)
        response = self.session.post(request_url, data=data)

        return xmltodict.parse(response.text)['wildfire']['upload-file-info']

    def submit_url(self, urls):
        request_url = "{0}{1}".format(self.root, "/submit/link")
        data = dict(apikey=self.key, link=urls)
        response = self.session.post(request_url, data=data)

        multi = False
        if type(urls) == list:
            if len(urls) == 1:
                urls = urls[0]
            elif len(urls) > 1:
                multi = True
        if multi:
            request_url = "{0}{1}".format(self.root, "/submit/links")
            url_file = list_to_file(urls)
            files = dict(file=("urls", url_file))
            data = dict(apikey=self.key)
            response = self.session.post(request_url, data=data, files=files)
            results = xmltodict.parse(response.text)['wildfire']['submit-link-info']
            for i in range(len(results)):
                results[i]["verdict"] = WildFire.verdicts[int(results[i]["verdict"])]
        else:
            request_url = "{0}{1}".format(self.root, "/get/verdict")
            data = dict(apikey=self.key, url=urls)
            response = self.session.post(request_url, data=data)
            results = xmltodict.parse(response.text)['wildfire']['submit-link-info']

        return results

    def _get_report(self, file_hash, report_format, stream=False):
        request_url = "{0}{1}".format(self.root, "/get/report")
        data = dict(apikey=self.key, hash=file_hash, format=report_format)
        response = self.session.post(request_url, data=data, stream=stream)
        if report_format == "pdf":
            response = response.content
        else:
            response = xmltodict.parse(response.text)["wildfire"]

        return response

    def get_report(self, file_hash):
        return self._get_report(file_hash, 'xml')

    def get_pdf_report(self, file_hash):
        return  self._get_report(file_hash, 'pdf', stream=True)

    def get_sample(self, file_hash):
        request_url = "{0}{1}".format(self.root, "/get/sample")
        data = dict(apikey=self.key, hash=file_hash)

        return self.session.post(request_url, data=data, stream=True).content

    def get_pcap(self, file_hash, platform=None):
        request_url = "{0}{1}".format(self.root, "/get/pcap")
        data = dict(apikey=self.key, hash=file_hash)
        if platform is not None:
            data['platform'] = platform

        return self.session.post(request_url, data=data, stream=True).content

    def get_malware_test_file(self):
        return self.session.get("{0}{1}".format(self.root, "/test/pe"), stream=True).content
