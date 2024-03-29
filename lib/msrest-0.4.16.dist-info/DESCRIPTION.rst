AutoRest: Python Client Runtime
================================

.. image:: https://travis-ci.org/Azure/msrest-for-python.svg?branch=master
 :target: https://travis-ci.org/Azure/msrest-for-python

.. image:: https://codecov.io/gh/azure/msrest-for-python/branch/master/graph/badge.svg
 :target: https://codecov.io/gh/azure/msrest-for-python

Installation
------------

To install:

.. code-block:: bash

    $ pip install msrest


Release History
---------------

2017-10-05 Version 0.4.16
+++++++++++++++++++++++++

**Bugfixes**

- Fix regression: accept "set<str>" as a valid "[str]" (#60)

2017-09-28 Version 0.4.15
+++++++++++++++++++++++++

**Bugfixes**

- Always log response body (#16)
- Improved exception message if error JSON is Odata v4 (#55)
- Refuse "str" as a valid "[str]" type (#41)
- Better exception handling if input from server is not JSON valid

**Features**

- Add Configuration.session_configuration_callback to customize the requests.Session if necessary (#52)
- Add a flag to Serializer to disable client-side-validation (#51)
- Remove "import requests" from "exceptions.py" for apps that require fast loading time (#23)

Thank you to jayden-at-arista for his contribution

2017-08-23 Version 0.4.14
+++++++++++++++++++++++++

**Bugfixes**

- Fix regression introduced in msrest 0.4.12 - dict syntax with enum modeled as string and enum used

2017-08-22 Version 0.4.13
+++++++++++++++++++++++++

**Bugfixes**

- Fix regression introduced in msrest 0.4.12 - dict syntax using isodate.Duration (#42)

2017-08-21 Version 0.4.12
+++++++++++++++++++++++++

**Features**

- Input is now more lenient
- Model have a "validate" method to check content constraints
- Model have now 4 new methods:

  - "serialize" that gives the RestAPI that will be sent
  - "as_dict" that returns a dict version of the Model. Callbacks are available.
  - "deserialize" the parses the RestAPI JSON into a Model
  - "from_dict" that parses several dict syntax into a Model. Callbacks are available.

More details and examples in the Wiki article on Github:
https://github.com/Azure/msrest-for-python/wiki/msrest-0.4.12---Serialization-change

**Bugfixes**

- Better Enum checking (#38)

2017-06-21 Version 0.4.11
+++++++++++++++++++++++++

**Bugfixes**

- Fix incorrect dependency to "requests" 2.14.x, instead of 2.x meant in 0.4.8

2017-06-15 Version 0.4.10
+++++++++++++++++++++++++

**Features**

- Add requests hooks to configuration

2017-06-08 Version 0.4.9
++++++++++++++++++++++++

**Bugfixes**

- Accept "null" value for paging array as an empty list and do not raise (#30)

2017-05-22 Version 0.4.8
++++++++++++++++++++++++

**Bugfixes**

- Fix random "pool is closed" error (#29)
- Fix requests dependency to version 2.x, since version 3.x is annunced to be breaking.

2017-04-04 Version 0.4.7
++++++++++++++++++++++++

**BugFixes**

- Refactor paging #22:

   - "next" is renamed "advance_page" and "next" returns only 1 element (Python 2 expected behavior)
   - paging objects are now real generator and support the "next()" built-in function without need for "iter()"

- Raise accurate DeserialisationError on incorrect RestAPI discriminator usage #27
- Fix discriminator usage of the base class name #27
- Remove default mutable arguments in Clients #20
- Fix object comparison in some scenarios #24

2017-03-06 Version 0.4.6
++++++++++++++++++++++++

**Bugfixes**

- Allow Model sub-classes to be serialized if type is "object"

2017-02-13 Version 0.4.5
++++++++++++++++++++++++

**Bugfixes**

- Fix polymorphic deserialization #11
- Fix regexp validation if '\\w' is used in Python 2.7 #13
- Fix dict deserialization if keys are unicode in Python 2.7

**Improvements**

- Add polymorphic serialisation from dict objects
- Remove chardet and use HTTP charset declaration (fallback to utf8)

2016-09-14 Version 0.4.4
++++++++++++++++++++++++

**Bugfixes**

- Remove paging URL validation, part of fix https://github.com/Azure/autorest/pull/1420

**Disclaimer**

In order to get paging fixes for impacted clients, you need this package and Autorest > 0.17.0 Nightly 20160913

2016-09-01 Version 0.4.3
++++++++++++++++++++++++

**Bugfixes**

- Better exception message (https://github.com/Azure/autorest/pull/1300)

2016-08-15 Version 0.4.2
++++++++++++++++++++++++

**Bugfixes**

- Fix serialization if "object" type contains None (https://github.com/Azure/autorest/issues/1353)

2016-08-08 Version 0.4.1
++++++++++++++++++++++++

**Bugfixes**

- Fix compatibility issues with requests 2.11.0 (https://github.com/Azure/autorest/issues/1337)
- Allow url of ClientRequest to have parameters (https://github.com/Azure/autorest/issues/1217)

2016-05-25 Version 0.4.0
++++++++++++++++++++++++

This version has no bug fixes, but implements new features of Autorest:
- Base64 url type
- unixtime type
- x-ms-enum modelAsString flag

**Behaviour changes**

- Add Platform information in UserAgent
- Needs Autorest > 0.17.0 Nightly 20160525

2016-04-26 Version 0.3.0
++++++++++++++++++++++++

**Bugfixes**

- Read only values are no longer in __init__ or sent to the server (https://github.com/Azure/autorest/pull/959)
- Useless kwarg removed

**Behaviour changes**

- Needs Autorest > 0.16.0 Nightly 20160426


2016-03-25 Version 0.2.0
++++++++++++++++++++++++

**Bugfixes**

- Manage integer enum values (https://github.com/Azure/autorest/pull/879)
- Add missing application/json Accept HTTP header (https://github.com/Azure/azure-sdk-for-python/issues/553)

**Behaviour changes**

- Needs Autorest > 0.16.0 Nightly 20160324


2016-03-21 Version 0.1.3
++++++++++++++++++++++++

**Bugfixes**

- Deserialisation of generic resource if null in JSON (https://github.com/Azure/azure-sdk-for-python/issues/544)


2016-03-14 Version 0.1.2
++++++++++++++++++++++++

**Bugfixes**

- urllib3 side effect (https://github.com/Azure/autorest/issues/824)


2016-03-04 Version 0.1.1
++++++++++++++++++++++++

**Bugfixes**

- Source package corrupted in Pypi (https://github.com/Azure/autorest/issues/799)

2016-03-04 Version 0.1.0
+++++++++++++++++++++++++

**Behavioural Changes**

- Removed custom logging set up and configuration. All loggers are now children of the root logger 'msrest' with no pre-defined configurations.
- Replaced _required attribute in Model class with more extensive _validation dict.

**Improvement**

- Removed hierarchy scanning for attribute maps from base Model class - relies on generator to populate attribute
  maps according to hierarchy.
- Base class Paged now inherits from collections.Iterable.
- Data validation during serialization using custom parameters (e.g. max, min etc).
- Added ValidationError to be raised if invalid data encountered during serialization.

2016-02-29 Version 0.0.3
++++++++++++++++++++++++

**Bugfixes**

- Source package corrupted in Pypi (https://github.com/Azure/autorest/issues/718)

2016-02-19 Version 0.0.2
++++++++++++++++++++++++

**Bugfixes**

- Fixed bug in exception logging before logger configured.

2016-02-19 Version 0.0.1
++++++++++++++++++++++++

- Initial release.


