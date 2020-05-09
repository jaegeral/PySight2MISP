PySight 1.3 (2020-05-08)
===========================
- Improvements in Threading.
- Don't log Pymisp output in debug mode to avoid disclosure of authorization keys.
- Remove simplejson from the requirements as it isn't used. Instead, list datetime as a requirement.

PySight 1.2 (2020-03-27)
===========================
- Add a comment in `README.md` regarding required access rights in MISP.
- Add a configuration option for the logging level and clean up logging.
- Bug fix to set the date when iSight doesn't provide a date.
- FireEye iSight reports can contain multiple ThreatScapes. This is taken into account now.
- For the malware family in iSight reports, use the "antivirus detection" category in MISP instead of 
"payload installation".
- When iSight provides an IP address in combination with a port, we always assume that it's a destination IP address.

PySight 1.1.2 (2020-02-24)
===========================
- Tagging of attributes didn't work yet. This bug has been fixed.
- Updated the example config file.
- Tried to make test_pysight.py work again, but didn't succeed.

PySight 1.1.1 (2020-02-14)
===========================
- Don't create filename attributes when the file's name is UNKNOWN (case insensitive).
- Improvements to comments of attributes and objects.
- Don't create ip address attributes when the IP address is provided in addition to a hostname.
- Remove the function to test connectivity to the FireEye iSight API.
- Create hostname|port attributes if both values are provided by FireEye iSight.
- Fix a mistake in adding comments to MISP objects.
- Remove the option to sleep in non-threaded processing.

PySight 1.1 (2020-02-11)
===========================
- Add configuration option for number of threads.
- Intercept response code 204 from FireEye iSight API.
- Differentiate whether a proxy shall be used for the FireEye iSight API, for MISP, or for both.
- Proper handling of publishDate data in pySightReport.py.
- Replace PyMISP with ExpandedPyMISP.
- Expand mapping of iSight fields to MISP objects, attributes and tags.

PySight 1.0.10 (2019-08-07)
===========================
- remove proxymanager

PySight 1.0.10 (2017-09-02)
===========================
- added Tag for C2 Attribute based

PySight 1.0.9 (2017-04-03)
===========================
- fixed date issue with reports (strings instead of float values in seconds)

PySight 1.0.8 (2017-01-25)
===========================
- started with attribute level tagging
- made it python3 ready
- adjusted the requirements
- added *.log to gitignore

PySight 1.0.7 (2016-11-25)
===========================
- intro of requirements.txt
- added some stuff to example config
- refactored a lot of variables
- removed a lot of issues
- added threading option and sleep time to config
- added C2 as bool in PySightReport
- added C2 check in File to add tags in the future as well
- added C2 example in test_data
- added other example file from https://docs.fireeye.com/iSight/index.html#/report_download
- removed threat actor other

PySight 1.0.6 (2016-11-04)
===========================
- initial version to be used with prod MISP
- fixed time / date issue

PySight 0.0.6 (2016-10-31)
===========================
- introducing test cases
- code cleaning
- new signatures for some methods

PySight 0.0.5 (2016-09-29)
===========================
- disable log messages from the Requests library
- remove file size temporary to reduce noise in an event

PySight 0.0.4 (2016-09-27)
===========================
- https://git.gcert.basf.net/fireeye/PySight/issues/3
- https://git.gcert.basf.net/fireeye/PySight/issues/5

PySight 0.0.3 (2016-09-26)
===========================
- modified pySightReport
- error handling
- better correlation
- improved parsing a lot
- pushed first sets to prod MISP
- logging to file
- saving of each indicator set to a file

PySight 0.0.2 (2016-09-21)
===========================
- added pySightReport.py
- added Changelog
- API with iSight is working

PySight 0.0.1 (2016-09-20)
===========================
init
