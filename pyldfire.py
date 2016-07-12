# -*- coding: utf-8 -*-
"""A Python module for Palo Alto Networks' WildFire API

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

from io import BytesIO

from requests import Session
import xmltodict

__author__ = 'Sean Whalen'
__version__ = '7.1.3'


def _list_to_file(l):
    """Converts a list to a BytesIO object. One item per line"""
    return BytesIO('\n'.join(l))


class WildFireException(RuntimeError):
    """This exception is raised when an API error occurs"""
    pass


class WildFire(object):
    _errors = {
        401: "API key is invalid",
        403: "Permission denied. This can occur when attempting to download benign or greyware samples.",
        404: "Not found",
        405: "Method other than POST used",
        413: "Sample file size over max limit",
        418: "Sample file type is not supported",
        419: "Max calls per day reached",
        421: "Invalid hash value",
        500: "Internal WildFire error",
        513: "File upload failed"
    }

    _verdicts = {
        0: "Benign",
        1: "Malware",
        2: "Greyware",
        -100: "Pending",
        -101: "Error",
        -102: "Not found"
    }

    @staticmethod
    def _raise_errors(response, *args, **kwargs):
        """Requests response processing hook"""
        if response.headers['content-type'].lower() == "text/xml" and len(response.text) > 0:
            results = xmltodict.parse(response.text)
            if "error" in results.keys():
                raise WildFireException(results["error"]["error-message"])
        if response.status_code != 200:
            raise WildFireException(WildFire._errors[response.status_code])

    def __init__(self, api_key, host="wildfire.paloaltonetworks.com", proxies=None, verify=True):
        """Initializes the WildFire class

        Args:
            api_key (str): A WildFire API Key
            host (str): The hostname of the WildFire service or appliance
            proxies (dict): An optional dictionary containing proxy data, with https as the key, and the proxy path
            as the value
            verify (bool): Verify the certificate
            verify (str): A path to a CA cert bundle
        """

        self.api_key = api_key
        self.host = host
        self.api_root = "https://{0}{1}".format(self.host, "/publicapi")
        self.session = Session()
        self.session.proxies = proxies
        self.session.verify = verify
        self.session.hooks = dict(response=WildFire._raise_errors)
        self.session.headers.update({"User-Agent": "pyldfire/{0}".format(__version__)})

    def get_verdicts(self, file_hashes):
        """Gets the verdict for one or more samples

        Args:
            file_hashes (list): A list of file hash strings
            file_hashes (str): A single file hash

        Returns:
            str: If a single file hash is passed, a string containing the verdict
            list: If multiple hashes a passed, a list of corresponding list of verdict strings

            Possible values:

            'Benign'
            'Malware'
            'Greyware'
            'Pending`
            'Error'
            'Not found`

        Raises:
            WildFireException: If an API error occurs
        """

        multi = False
        if type(file_hashes) == list:
            if len(file_hashes) == 1:
                file_hashes = file_hashes[0]
            elif len(file_hashes) > 1:
                multi = True
        if multi:
            request_url = "{0}{1}".format(self.api_root, "/get/verdicts")
            hash_file = _list_to_file(file_hashes)
            files = dict(file=("hashes", hash_file))
            data = dict(apikey=self.api_key)
            response = self.session.post(request_url, data=data, files=files)
            results = xmltodict.parse(response.text)['wildfire']['get-verdict-info']
            for i in range(len(results)):
                results[i]["verdict"] = WildFire._verdicts[int(results[i]["verdict"])]
            results = map(lambda result: result["verdict"], results)
        else:
            request_url = "{0}{1}".format(self.api_root, "/get/verdict")
            data = dict(apikey=self.api_key, hash=file_hashes)
            response = self.session.post(request_url, data=data)
            verdict = int(xmltodict.parse(response.text)['wildfire']['get-verdict-info']['verdict'])
            results = WildFire._verdicts[verdict]

        return results

    def submit_file(self, file_obj, filename="sample"):
        """Submits a file to WildFire for analysis

        Args:
            file_obj (file): The file to send
            filename (str): An optional filename

        Returns:
            dict: Analysis results

        Raises:
             WildFireException: If an API error occurs
        """

        url = "{0}{1}".format(self.api_root, "/submit/file")
        data = dict(apikey=self.api_key)
        files = dict(file=(filename, file_obj))
        response = self.session.post(url, data=data, files=files)

        return xmltodict.parse(response.text)['wildfire']['upload-file-info']

    def submit_remote_file(self, url):
        """Submits a file from a remote URL for analysis

        Args:
            url (str): The URL where the file is located

        Returns:
            dict: Analysis results

        Raises:
             WildFireException: If an API error occurs

        Notes:
            This is for submitting files located at remote URLs, not web pages.

        See Also:
            submit_urls(self, urls)
        """

        request_url = "{0}{1}".format(self.api_root, "/submit/url")
        data = dict(apikey=self.api_key, url=url)
        response = self.session.post(request_url, data=data)

        return xmltodict.parse(response.text)['wildfire']['upload-file-info']

    def submit_urls(self, urls):
        """
        Submits one or more URLs to a web page for analysis

        Args:
            urls (str): A single URL
            urls (list): A list of URLs

        Returns:
            dict: If a single URL is passed, a dictionary of analysis results
            list: If multiple URLs are passed, a list of corresponding dictionaries containing analysis results

        Raises:
             WildFireException: If an API error occurs
        """

        multi = False
        if type(urls) == list:
            if len(urls) == 1:
                urls = urls[0]
            elif len(urls) > 1:
                multi = True
        if multi:
            request_url = "{0}{1}".format(self.api_root, "/submit/links")
            url_file = _list_to_file(urls)
            files = dict(file=("urls", url_file))
            data = dict(apikey=self.api_key)
            response = self.session.post(request_url, data=data, files=files)
            results = xmltodict.parse(response.text)['wildfire']['submit-link-info']
            for i in range(len(results)):
                results[i]["verdict"] = WildFire._verdicts[int(results[i]["verdict"])]
        else:
            request_url = "{0}{1}".format(self.api_root, "/submit/link")
            data = dict(apikey=self.api_key, url=urls)
            response = self.session.post(request_url, data=data)
            results = xmltodict.parse(response.text)['wildfire']['submit-link-info']

        return results

    def _get_report(self, file_hash, report_format, stream=False):
        """An internal method for retrieving analysis reports
        Args:
            file_hash (str):  A hash of a sample
            report_format (str): either xml or pdf
            stream (bool): Stream the HTTP download. Useful for binary data.

        Returns:
            dict: Analysis results
            bytes: PDF bytes

        Raises:
             WildFireException: If an API error occurs
        """

        request_url = "{0}{1}".format(self.api_root, "/get/report")
        data = dict(apikey=self.api_key, hash=file_hash, format=report_format)
        response = self.session.post(request_url, data=data, stream=stream)
        if report_format == "pdf":
            response = response.content
        else:
            response = xmltodict.parse(response.text)["wildfire"]

        return response

    def get_report(self, file_hash):
        """Gets analysis results as structured data
        Args:
            file_hash (str): A hash of a sample

        Returns:
            dict: Analysis results

        Raises:
            WildFireException: If an API error occurs
        """

        return self._get_report(file_hash, 'xml')

    def get_pdf_report(self, file_hash):
        """Gets analysis results as a PDF
        Args:
            file_hash: A hash of a sample of a file

        Returns:
            bytes: The PDF

        Raises:
             WildFireException: If an API error occurs
        """
        return self._get_report(file_hash, 'pdf', stream=True)

    def get_sample(self, file_hash):
        """Gets a sample file
        Args:
            file_hash (str): A hash of a sample

        Returns:
            bytes: The sample

        Raises:
             WildFireException: If an API error occurs
        """
        request_url = "{0}{1}".format(self.api_root, "/get/sample")
        data = dict(apikey=self.api_key, hash=file_hash)

        return self.session.post(request_url, data=data, stream=True).content

    def get_pcap(self, file_hash, platform=None):
        """Gets a PCAP from a sample analysis
            Args:
                file_hash (str): A hash of a sample
                platform (int): One of the following integers:

                1: Windows XP, Adobe Reader 9.3.3, Office 2003
                2: Windows XP, Adobe Reader 9.4.0, Flash 10, Office 2007
                3: Windows XP, Adobe Reader 11, Flash 11, Office 2010
                4: Windows 7 32-bit, Adobe Reader 11, Flash 11, Office 2010
                5: Windows 7 64bit, Adobe Reader 11, Flash 11, Office 2010
                50: Mac OS X Mountain Lion
                201: Android 2.3, API 10, avd2.3.

            Returns:
                bytes: The PCAP

            Raises:
                 WildFireException: If an API error occurs
            """

        request_url = "{0}{1}".format(self.api_root, "/get/pcap")
        data = dict(apikey=self.api_key, hash=file_hash)
        if platform is not None:
            data['platform'] = platform

        return self.session.post(request_url, data=data, stream=True).content

    def get_malware_test_file(self):
        """Gets a unique, benign malware test file that will trigger an alert on Palo Alto Networks' firewalls

        Returns:
            bytes: A malware test file
        """

        return self.session.get("{0}{1}".format(self.api_root, "/test/pe"), stream=True).content
