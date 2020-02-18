pyldfire
========

A Python module for `Palo Alto Networks\` WildFire API`_

::

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

Features
--------

-  Python 2 and 3 support
-  Returns native Python objects
- Raises exceptions on API errors with error details
-  Supports HTTPS proxies and SSL/TLS validation
-  Supports WildFire cloud or appliance
-  Supports all WildFire 8.1 API calls

   -  Uploading sample files and URLs
   -  Getting verdicts
   -  Getting full reports in PDF or dictionary formats
   -  Getting samples
   -  Getting PCAPs
   -  Getting a malware test file

Examples
--------

::

    json import dumps
    from io import BytesIO

    from pyldfire import WildFire

    printer = PrettyPrinter(indent=2)

    wildfire = WildFire("api-key-goes-here")

    # Submit a local file
    with open("malware", "rb") as sample_file:
        results = wildfire.submit_file(sample_file)
    dumps(results)

    # File Hashes can be MD5,SHA1, or SHA256
    file_hash = "419251150a2f77422efa1e016d605d69"

    # Download a sample to a file
    with open("sample", "wb") as sample_file:
        sample_file.write(wildfire.get_sample(file_hash))

    # Or keep it as a file-like object in memory instead
    sample = BytesIO(wildfire.get_sample(file_hash))

    # Same for PCAPs and PDF reports

    # Get a verdict
    verdict = wildfire.get_verdicts([file_hash])

    # Get analysis results
    results = wildfire.get_report(file_hash)

    # Test your firewall
    wildfire.get_malware_test_file()

pyldfire.WildFire methods
-------------------------

``__init__(self, api_key, host='wildfire.paloaltonetworks.com', proxies=None, verify=True)``

Initializes the WildFire class

::

     Args:
         api_key (str): A WildFire API Key
         host (str): The hostname of the WildFire service or appliance
         proxies (dict): An optional dictionary containing proxy data,
         with https as the key, and the proxy path as the value
         verify (bool): Verify the certificate
         verify (str): A path to a CA cert bundle

``get_malware_test_file(self)``

Gets a unique, benign malware test file that will trigger an alert on
Palo Alto Networks’ firewalls

::

     Returns:
         bytes: A malware test file

``get_pcap(self, file_hash, platform=None)``

Gets a PCAP from a sample analysis

::

     Args:
         file_hash (str): A hash of a sample
         platform (int): One of the following integers:

         WildFire Private and Global Cloud

          1: Windows XP, Adobe Reader 9.3.3, Office 2003
          2: Windows XP, Adobe Reader 9.4.0, Flash 10, Office 2007
          3: Windows XP, Adobe Reader 11, Flash 11, Office 2010
          4: Windows 7 32-bit, Adobe Reader 11, Flash 11, Office 2010
          5: Windows 7 64-bit, Adobe Reader 11, Flash 11, Office 2010
          100: PDF Static Analyzer
          101: DOC/CDF Static Analyzer
          102: Java/Jar Static Analyzer
          103: Office 2007 Open XML Static Analyzer
          104: Adobe Flash Static Analyzer
          204: PE Static Analyzer

        WildFire Global Cloudonly

          6: Windows XP, Internet Explorer 8, Flash 11
          20: Windows XP, Adobe Reader 9.4.0, Flash 10, Office 2007
          21: Windows 7, Flash 11, Office 2010
          50: Mac OSX Mountain Lion
          60: Windows XP, Adobe Reader 9.4.0, Flash 10, Office 2007
          61: Windows 7 64-bit, Adobe Reader 11, Flash 11, Office 2010
          66: Windows 10 64-bit, Adobe Reader 11, Flash 22, Office 2010
          105: RTF Static Analyzer
          110: Max OSX Static Analyzer
          200: APK Static Analyzer
          201: Android 2.3, API 10, avd2.3.1
          202: Android 4.1, API 16, avd4.1.1 X86
          203: Android 4.1, API 16, avd4.1.1 ARM
          205: Phishing Static Analyzer
          206: Android 4.3, API 18, avd4.3 ARM
          300: Windows XP, Internet Explorer 8, Flash 13.0.0.281, Flash
          16.0.0.305, Elink Analyzer
          301: Windows 7, Internet Explorer 9, Flash 13.0.0.281, Flash
          17.0.0.169, Elink Analyzer
          302: Windows 7, Internet Explorer 10, Flash 16.0.0.305, Flash
          17.0.0.169, Elink Analyzer
          303: Windows 7, Internet Explorer 11, Flash 16.0.0.305, Flash
          17.0.0.169, Elink Analyzer
          400: Linux (ELF Files)
          501: BareMetal Windows 7 x64, Adobe Reader 11, Flash 11,
          Office 2010
          800: Archives (RAR and 7-Zip files)
     Returns:
         bytes: The PCAP

     Raises:
          WildFireException: If an API error occurs

``get_pdf_report(self, file_hash)``

Gets analysis results as a PDF

::

     Args:
         file_hash: A hash of a sample of a file

     Returns:
         bytes: The PDF

     Raises:
          WildFireException: If an API error occurs

``get_report(self, file_hash)``

Gets analysis results as structured data

::

     Args:
         file_hash (str): A hash of a sample

     Returns:
         dict: Analysis results

     Raises:
             WildFireException: If an API error occurs

``get_sample(self, file_hash)``

Gets a sample file

::

     Args:
         file_hash (str): A hash of a sample

     Returns:
         bytes: The sample

     Raises:
             WildFireException: If an API error occurs

``get_verdicts(self, file_hashes)``

Gets the verdict for one or more samples

::

     Args:
            file_hashes (list): A list of file hash strings
            file_hashes (str): A single file hash

        Returns:
            str: If a single file hash is passed, a string containing the verdict
            list: If multiple hashes a passed, a list of corresponding list of verdict strings

            Possible values:

            'benign'
            'malware'
            'greyware'
            'phishing'
            'pending`
            'error'
            'not found`

        Raises:
            WildFireException: If an API error occurs

``change_sample_verdict(self, sha256_hash, verdict, comment)``

Change a sample's verdict

::
    Notes:
            Available on WildFire appliances only

    Args:
        sha256_hash (str): The SHA-256 hash of the sample
        verdict (str): The new verdict to set
        verdict (int): The new verdict to set
        comment (str): A comment describing the reason for the verdict change

    Returns:
        str: A response message

    Raises:
        WildFireException: If an API error occurs

``get_changed_verdicts(self, date)``

Returns a list of samples with changed WildFire appliance verdicts

::

    Args:
            date (str): A starting date in ``YYY-MM-DD`` format

    Notes:
        This feature is only available on WildFire appliances.
        Changed verdicts can only be obtained for the past 14 days.

    Returns:
        list: A list of samples with changed WildFire appliance verdicts

``submit_file(self, file_obj, filename="sample")``

Submits a file to WildFire for analysis

::

     Args:
            file_obj (file): The file to send
            filename (str): An optional filename

        Returns:
            dict: Analysis results

        Raises:
             WildFireException: If an API error occurs


``submit_remote_file(self, url)``

Submits a file from a remote URL for analysis

::

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

``submit_urls(self, urls)``

Submits one or more URLs to a web page for analysis

::

     Args:
            urls (str): A single URL
            urls (list): A list of URLs

        Returns:
            dict: If a single URL is passed, a dictionary of analysis results
            list: If multiple URLs are passed, a list of corresponding dictionaries containing analysis results

        Raises:
             WildFireException: If an API error occurs

.. _Palo Alto Networks\` WildFire API: https://www.paloaltonetworks.com/documentation/81/wildfire/wf_api

