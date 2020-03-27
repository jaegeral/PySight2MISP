#!/usr/bin/env python

# pySightReport - Python class for parsing iSightReport json alerts
#
# Alexander Jaeger (deralexxx)
#
# The MIT License (MIT) see https://github.com/deralexxx/FireMISP/blob/master/LICENSE
#
# For documentation of iSight indicator fields, see
# https://docs.fireeye.com/iSight/index.html#/field_definitions and
# https://docs.fireeye.com/iSight/index.html#/indicators
#

from datetime import datetime
import logging
# Regular expressions are not used yet.
# Potentially they might be required to split registry fields into hive, key and value.
#import re
import time

#reload(sys)
#sys.setdefaultencoding('utf-8')

# Initialize the logger
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')


class pySightReport (object):
    def __init__(self, a_alert_json):
        """
        :param a_alert_json:
        :type a_alert_json:
        :rtype: object
        """

        # Initialize all potential fields of the FireEye iSight report
        self.alert = a_alert_json

        # General information
        self.reportId = None
        self.title = None  # Cutwail Botnet Distributes Recruitment Mass Mailings
        self.publishDate = None  # 1469544180
        self.ThreatScape = None  # Cyber Espionage
        self.riskRating = None  # High
        self.audience = None  # Operational
        self.intelligenceType = None  # threat / malware / vulnerability / overview
        self.reportLink = None  # https:#api.isightpartners.com/report/16-00011458
        self.webLink = None  # https:#mysight.isightpartners.com/report/full/16-00011458

        # Email-related indicators
        self.emailIdentifier = None  # Attacker
        self.senderAddress = None  # lissddzz@gmail.com
        self.senderName = None  # lissddzz
        self.sourceDomain = None  # samyongonc.com
        self.sourceIP = None  # 184.105.137.110
        self.subject = None  # Administrator Manager position
        self.recipient = None  # yeh@cwb.gov.tw
        self.emailLanguage = None  # English

        # File-related indicators
        self.fileName = None  # TW2BBFF500.doc
        self.fileSize = None  # 14860
        self.fuzzyHash = None  # 384:AmHWrWG6qqrx7F7ByIvjgS+S0SBS1n9dwnHJWNy/4yAOksmSfsF17BtX7K4:qrWG6qqV7F7ByIvjgS+S0SBSd9dwnHJw
        self.fileIdentifier = None  # Related
        self.md5 = None  # d27eb3f18ba7f3ae6fa793630882652f
        self.sha1 = None  # 4559ba637772b681dee07127c7c17c776455138e
        self.sha256 = None  # e9c60a120db8a4366734dcecbc15ddd4510ef7929cc7a5d21529180494a35cdc
        self.description = None  # Keylogger
        self.fileType = None  # Rich Text Format data, version 1, ANSI
        self.packer = None  # Armadillo v1.xx - v2.xx
        self.registry = None  # HKEY_LOCAL_MACHINE\SOFTWARE\CBSTEST
        self.registryHive = None  # HKEY_LOCAL_MACHINE
        self.registryKey = None  # Software\Microsoft\Windows\CurrentVersion\RunOnce
        self.registryValue = None  # SilentApp
        self.fileCompilationDateTime = None  # 1371573858
        self.filePath = None  # /tmp/adversary/test

        # Network-related indicators
        self.userAgent = None  # Mozilla
        self.asn = None  # 26272
        self.cidr = None  # 1.179.132.0/24
        self.domain = None  # webmonder.gicp.net
        self.domainTimeOfLookup = None  # 1371573858
        self.networkIdentifier = None  # Attacker
        self.ip = None  # 112.121.182.148
        self.port = None  # 80
        self.protocol = None  # TCP
        self.registrantEmail = None  # sammyguy@gmail.com
        self.registrantName = None  # Vanella Salvatore
        self.url = None  # http://www.google.com
        self.networkType = None  # C&C

        # Context
        self.malwareFamily = None  # Dyre
        self.malwareFamilyId = None  # 42bceb96-13c5-4b3f-a435-92ad9b17db27
        self.actor = None  # actor-oldms
        self.actorId = None  # c9fc4d46-516b-4fdb-8272-2798d2cdf0bd
        self.observationTime = None  # 1469544180

        # After initialization, parse the report and assign all available values
        self._parse_json(a_alert_json)


    def _parse_json(self, p_alert_json):
        """
        :param p_alert_json:
        :type p_alert_json:
        """
        if not p_alert_json:
            raise ValueError('No Json given')

        if "reportId" in p_alert_json and p_alert_json['reportId'] is not None:
            self.reportId = str(p_alert_json['reportId'])
        if 'title' in p_alert_json and p_alert_json['title'] is not None:
            self.title = str(p_alert_json['title'])
        if 'publishDate' in p_alert_json and p_alert_json['publishDate'] is not None:
            if isinstance(p_alert_json['publishDate'],int):
                self.publishDate = p_alert_json['publishDate']
            # If publishDate is not in epoch format, i.e. not an integer, we suppose it to be human readable,
            # e.g. "October 11, 2016 07:20:00 AM", and convert it to integer epoch format
            else:
                logger.debug('Converting date %s to an epoch format', p_alert_json['publishDate'])
                date_format = '%B %d, %Y %H:%M:%S %p'
                datetime_object = datetime.strptime(p_alert_json['publishDate'], date_format)
                timestamp = time.mktime(datetime_object.timetuple())
                self.publishDate = int(timestamp)
        if 'ThreatScape' in p_alert_json and p_alert_json['ThreatScape'] is not None:
            self.ThreatScape = str(p_alert_json['ThreatScape'])
        if 'audience' in p_alert_json and p_alert_json['audience'] is not None:
            self.audience = str(p_alert_json['audience'])
        if 'intelligenceType' in p_alert_json and p_alert_json['intelligenceType'] is not None:
            self.intelligenceType = str(p_alert_json['intelligenceType'])
        if 'reportLink' in p_alert_json and p_alert_json['reportLink'] is not None:
            self.reportLink = str(p_alert_json['reportLink'])
        if 'webLink' in p_alert_json and p_alert_json['webLink'] is not None:
            self.webLink = str(p_alert_json['webLink'])
            # Split it to get the ma_id of the "alert-url"
            # ("https://fireeye.foo.bar/event_stream/events_for_bot?ma_id=12345678")
            #self.alert_ma_id = (self.alert_url.split("="))[1]
        if 'emailIdentifier' in p_alert_json and p_alert_json['emailIdentifier'] is not None:
            self.emailIdentifier = str(p_alert_json['emailIdentifier'])
        if 'senderAddress' in p_alert_json and p_alert_json['senderAddress'] is not None:
            self.senderAddress = str(p_alert_json['senderAddress'])
        if 'senderName' in p_alert_json and p_alert_json['senderName'] is not None:
            self.senderName = str(p_alert_json['senderName'])
        if 'sourceDomain' in p_alert_json and p_alert_json['sourceDomain'] is not None:
            self.sourceDomain = str(p_alert_json['sourceDomain'])
        if 'sourceIP' in p_alert_json and p_alert_json['sourceIP'] is not None:
            self.sourceIP = str(p_alert_json['sourceIP'])
        if 'subject' in p_alert_json and p_alert_json['subject'] is not None:
            self.subject = str(p_alert_json['subject'])
        if 'recipient' in p_alert_json and p_alert_json['recipient'] is not None:
            self.recipient = str(p_alert_json['recipient'])
        if 'emailLanguage' in p_alert_json and p_alert_json['emailLanguage'] is not None:
            self.emailLanguage = str(p_alert_json['emailLanguage'])
        if 'fileName' in p_alert_json and p_alert_json['fileName'] is not None:
            self.fileName = str(p_alert_json['fileName'])
        if 'fileSize' in p_alert_json and p_alert_json['fileSize'] is not None:
            self.fileSize = str(p_alert_json['fileSize'])
        if 'fuzzyHash' in p_alert_json and p_alert_json['fuzzyHash'] is not None:
            self.fuzzyHash = str(p_alert_json['fuzzyHash'])
        if 'fileIdentifier' in p_alert_json and p_alert_json['fileIdentifier'] is not None:
            self.fileIdentifier = str(p_alert_json['fileIdentifier'])
        if 'md5' in p_alert_json and p_alert_json['md5'] is not None:
            self.md5 = str(p_alert_json['md5'])
        if 'sha1' in p_alert_json and p_alert_json['sha1'] is not None:
            self.sha1 = str(p_alert_json['sha1'])
        if 'sha256' in p_alert_json and p_alert_json['sha256'] is not None:
            self.sha256 = str(p_alert_json['sha256'])
        if 'description' in p_alert_json and p_alert_json['description'] is not None:
            self.description = str(p_alert_json['description'])
        if 'fileType' in p_alert_json and p_alert_json['fileType'] is not None:
            self.fileType = str(p_alert_json['fileType'])
        if 'packer' in p_alert_json and p_alert_json['packer'] is not None:
            self.packer = str(p_alert_json['packer'])
        # TODO: Ideally, the registry field would be separated into hive, key and value.
        if 'registry' in p_alert_json and p_alert_json['registry'] is not None:
            self.registry = str(p_alert_json['registry'])
        if 'registryHive' in p_alert_json and p_alert_json['registryHive'] is not None:
            self.registryHive = str(p_alert_json['registryHive'])
        if 'registryKey' in p_alert_json and p_alert_json['registryKey'] is not None:
            self.registryKey = str(p_alert_json['registryKey'])
        if 'registryValue' in p_alert_json and p_alert_json['registryValue'] is not None:
            self.registryValue = str(p_alert_json['registryValue'])
        if 'fileCompilationDateTime' in p_alert_json and p_alert_json['fileCompilationDateTime'] is not None:
            if isinstance(p_alert_json['fileCompilationDateTime'], int):
                self.fileCompilationDateTime = p_alert_json['fileCompilationDateTime']
            # If fileCompilationDateTime is not in epoch format, i.e. not an integer, we suppose it to be human
            # readable, e.g. "October 11, 2016 07:20:00 AM", and convert it to integer epoch format.
            else:
                logger.debug('Converting timestamp %s to epoch fomat', p_alert_json['fileCompilationDateTime'])
                date_format = '%B %d, %Y %H:%M:%S %p'
                datetime_object = datetime.strptime(p_alert_json['fileCompilationDateTime'], date_format)
                timestamp = time.mktime(datetime_object.timetuple())
                self.fileCompilationDateTime = int(timestamp)
        if 'filePath' in p_alert_json and p_alert_json['filePath'] is not None:
            self.filePath = str(p_alert_json['filePath'])
        if 'userAgent' in p_alert_json and p_alert_json['userAgent'] is not None:
            self.userAgent = str(p_alert_json['userAgent'])
        if 'asn' in p_alert_json and p_alert_json['asn'] is not None:
            self.asn = str(p_alert_json['asn'])
        if 'cidr' in p_alert_json and p_alert_json['cidr'] is not None:
            self.cidr = str(p_alert_json['cidr'])
        if 'domain' in p_alert_json and p_alert_json['domain'] is not None:
            self.domain = str(p_alert_json['domain'])
        if 'domainTimeOfLookup' in p_alert_json and p_alert_json['domainTimeOfLookup'] is not None:
            if isinstance(p_alert_json['domainTimeOfLookup'], int):
                self.domainTimeOfLookup = p_alert_json['domainTimeOfLookup']
            # If domainTimeOfLookup is not in epoch format, i.e. not an integer, we suppose it to be human readable,
            # e.g. "October 11, 2016 07:20:00 AM", and convert it to integer epoch format
            else:
                logger.debug('Converting timestamp %s to epoch format', p_alert_json['domainTimeOfLookup'])
                date_format = '%B %d, %Y %H:%M:%S %p'
                datetime_object = datetime.strptime(p_alert_json['domainTimeOfLookup'], date_format)
                timestamp = time.mktime(datetime_object.timetuple())
                self.domainTimeOfLookup = int(timestamp)
        if 'networkIdentifier' in p_alert_json and p_alert_json['networkIdentifier'] is not None:
            self.networkIdentifier = str(p_alert_json['networkIdentifier'])
        if 'ip' in p_alert_json and p_alert_json['ip'] is not None:
            self.ip = str(p_alert_json['ip'])
        if 'port' in p_alert_json and p_alert_json['port'] is not None:
            self.port = str(p_alert_json['port'])
        if 'protocol' in p_alert_json and p_alert_json['protocol'] is not None:
            self.protocol = str(p_alert_json['protocol'])
        if 'registrantEmail' in p_alert_json and p_alert_json['registrantEmail'] is not None:
            self.registrantEmail = str(p_alert_json['registrantEmail'])
        if 'registrantName' in p_alert_json and p_alert_json['registrantName'] is not None:
            self.registrantName = str(p_alert_json['registrantName'])
        if 'url' in p_alert_json and p_alert_json['url'] is not None:
            self.url = str(p_alert_json['url'])
        if 'networkType' in p_alert_json and p_alert_json['networkType'] is not None:
            self.networkType = str(p_alert_json['networkType'])
        if 'malwareFamily' in p_alert_json and p_alert_json['malwareFamily'] is not None:
            self.malwareFamily = str(p_alert_json['malwareFamily'])
        if 'malwareFamilyId' in p_alert_json and p_alert_json['malwareFamilyId'] is not None:
            self.malwareFamilyId = str(p_alert_json['malwareFamilyId'])
        if 'actor' in p_alert_json and p_alert_json['actor'] is not None:
            self.actor = str(p_alert_json['actor'])
        if 'actorId' in p_alert_json and p_alert_json['actorId'] is not None:
            self.actorId = str(p_alert_json['actorId'])
        if 'observationTime' in p_alert_json and p_alert_json['observationTime'] is not None:
            if isinstance(p_alert_json['observationTime'], int):
                self.observationTime = p_alert_json['observationTime']
            # If observationTime is not in epoch format, i.e. not an integer, we suppose it to be human readable,
            # e.g. "October 11, 2016 07:20:00 AM", and convert it to integer epoch format
            else:
                logger.debug('Converting timestamp %s to epoch format', p_alert_json['observationTime'])
                date_format = '%B %d, %Y %H:%M:%S %p'
                datetime_object = datetime.strptime(p_alert_json['observationTime'], date_format)
                timestamp = time.mktime(datetime_object.timetuple())
                self.observationTime = int(timestamp)
        if 'riskRating' in p_alert_json and p_alert_json['riskRating'] is not None:
            self.riskRating = str(p_alert_json['riskRating'])

        logger.debug('Finished parsing %s', p_alert_json)
