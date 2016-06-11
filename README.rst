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

pyldfire.WildFire functions
---------------------------

``__init__(self, api_key, host='wildfire.paloaltonetworks.com', proxies=None, verify=True)``

Initializes the WildFire class

::

     Args:
         api_key (str): A WildFire API Key
         host (str): The hostname of the WildFire service or appliance
         proxies (dict): An optional dictionary containing proxy data, with https as the key, and the proxy path
         as the value
         verify (bool): Verify the certificate
         verify (str): A path to a CA cert bundle

``get_malware_test_file(self)``

Gets a unique, benign malware test file that will trigger an alert on
Palo Alto Networks’ firewalls

::

     Returns:
         bytes: A malware test file

``get_pcap(self, file_hash, platform=None)``

Gets a pcap from a sample analysis

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
         bytes: The PCAP bytes

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

.. _Palo Alto Networks\` WildFire API: https://www.paloaltonetworks.com/documentation/71/wildfire/wf_api

