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

- added pyISightReport.py
- added Changelog
- API with iSight is working


PySight 0.0.1 (2016-09-20)
===========================

init
