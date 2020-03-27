# What?

PySight2MISP is a project that can be run to be used as glue between [iSight intel API](https://docs.fireeye.com/iSight/index.html) and [MISP API](https://github.com/CIRCL/PyMISP).

# Status

This script is not maintaned - if you want to use it, there might be a need to fix a lot of stuff before, but still happy to accept PR.

# Why

To get indicators, IOCs etc. from FireEye iSight into a MISP system.

# How

    see INSTALL.md

It is recommended to have a "Publisher" account on the MISP system. A "sync user" account is not sufficient because it 
doesn't have enough rights (e.g. for tagging events).

You do not need an iSight account to test the script, there is test data to test with, e.g., a MISP VM.

# Roadmap

## Short term

* Fix [issues](issues).
* Add written report details per event.

## Long term

* Migrate stuff to a MISP import module.