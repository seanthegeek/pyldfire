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
-  Supports HTTPS proxies and SSL/TLS validation
-  Supports WildFire cloud or appliance
-  Supports all WildFire 7.1 API calls

   -  Uploading sample files and URLs
   -  Getting verdicts
   -  Getting full reports in PDF or dictionary formats
   -  Getting samples
   -  Getting PCAPs
   -  Getting a malware test file

Examples
--------

::

    from pprint import PrettyPrinter
    from io import BytesIO

    from pyldfire import WildFire

    printer = PrettyPrinter(indent=2)

    wildfire = WildFire("api-key-goes-here")

    # Submit a local file
    with open("malware", "rb") as sample_file:
        results = wildfire.submit_file(sample_file)
    printer.pprint(results)

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

            'Benign'
            'Malware'
            'Greyware'
            'Pending`
            'Error'
            'Not found`

        Raises:
            WildFireException: If an API error occurs


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

.. _Palo Alto Networks\` WildFire API: https://www.paloaltonetworks.com/documentation/71/wildfire/wf_api

