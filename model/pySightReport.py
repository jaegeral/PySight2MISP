#!/usr/bin/env python

# pySightReport - Python class for parsing iSightReport json alerts
#
# Alexander Jaeger (deralexxx)
#
# The MIT License (MIT) see https://github.com/deralexxx/FireMISP/blob/master/LICENSE
#
# Based on the idea of:
#

import re

from datetime import datetime
import simplejson as json
import logging



#import sys

#reload(sys)
#sys.setdefaultencoding('utf-8')


#init logger
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
        self.alert = a_alert_json
        self.alert_reportId = None
        self.ThreatScape = None  # Cyber Espionage
        self.audience = None  # Operational
        self.intelligenceType = None  # threat
        self.publishDate = None  # 1469544180
        self.reportLink = None  # https:#api.isightpartners.com/report/16-00011458
        self.webLink = None  # https:#mysight.isightpartners.com/report/full/16-00011458
        self.emailIdentifier = None  # null
        self.senderAddress = None  # null
        self.senderName = None  # null
        self.sourceDomain = None  # null
        self.sourceIp = None  # null
        self.subject = None  # null
        self.recipient = None  # null
        self.emailLanguage = None  # null
        self.fileName = None  # TW2BBFF500.doc
        self.fileSize = None  # 14860
        self.fuzzyHash = None  # 384:AmHWrWG6qqrx7F7ByIvjgS+S0SBS1n9dwnHJWNy/4yAOksmSfsF17BtX7K4:qrWG6qqV7F7ByIvjgS+S0SBSd9dwnHJw
        self.fileIdentifier = None  # Related
        self.md5 = None  # d27eb3f18ba7f3ae6fa793630882652f
        self.sha1 = None  # 4559ba637772b681dee07127c7c17c776455138e
        self.sha256 = None  # e9c60a120db8a4366734dcecbc15ddd4510ef7929cc7a5d21529180494a35cdc
        self.description = None  # null
        self.fileType = None  # Rich Text Format data, version 1, ANSI
        self.packer = None  # null
        self.userAgent = None  # null
        self.registry = None  # null
        self.fileCompilationDateTime = None  # null
        self.filePath = None  # null
        self.asn = None  # null
        self.cidr = None  # null
        self.domain = None  # null
        self.domainTimeOfLookup = None  # null
        self.networkIdentifier = None  # null
        self.ip = None  # null
        self.port = None  # null
        self.protocol = None  # null
        self.registrantEmail = None  # null
        self.registrantName = None  # null
        self.networkType = None  # null
        self.url = None  # null
        self.malwareFamily = None  # null
        self.malwareFamilyId = None  # null
        self.actor = None  # null
        self.actorId = None  # null
        self.observationTime = None  # 1469544180
        self.riskRating = None #High
        self.registryHive = None # HKEY_LOCAL_MACHINE
        self.registryKey = None #Software\Microsoft\Windows\CurrentVersion\RunOnce
        self.registryValue = None #SilentApp
        self.title = None
        self.isCommandAndControl = False
        self.networks_array = []



        # important: parse after initiate, otherwise values will be overwritten
        self._parse_json(a_alert_json)


    def _parse_json(self, p_alert_json):
        # Print out the Json given to the method
        #logger.debug(json.dumps(p_alert_json, sort_keys=False, indent=4, separators=(',', ': ')))

        """
        :param p_alert_json:
        :type p_alert_json:
        """
        if not p_alert_json:
            raise ValueError('No Json given')

        if "reportId" in p_alert_json:
            self.reportId = str(p_alert_json['reportId'])

        if 'webLink' in p_alert_json:
            self.webLink = str(p_alert_json['webLink'])
            #and split it to get the ma_id "alert-url": "https://fireeye.foo.bar/event_stream/events_for_bot?ma_id=12345678",
            #self.alert_ma_id = (self.alert_url.split("="))[1]

        if 'title' in p_alert_json:
            self.title = str(p_alert_json['title'])

        if 'ThreatScape' in p_alert_json and p_alert_json['ThreatScape'] is not None:
            self.ThreatScape = str(p_alert_json['ThreatScape'])

        if 'tagSection' in p_alert_json:
            # TODO: implement that
            logger.debug("asdds")
            # check if networks section in tags
            if 'networks' in p_alert_json['tagSection']:

                for current_network in p_alert_json['tagSection']['networks']['network']:

                    from model import network
                    current_network_2 = network.iSightNetwork(a_network_json=current_network)
                    self.networks_array.append(current_network_2)

                    logger.debug("network found! "+current_network_2.domain)


        if 'audience' in p_alert_json and p_alert_json['audience'] is not None:
            self.audience = str(p_alert_json['audience'])

        if 'intelligenceType' in p_alert_json and p_alert_json['intelligenceType'] is not None:
            self.intelligenceType = str(p_alert_json['intelligenceType'])

        if 'publishDate' in p_alert_json:
            if isinstance(p_alert_json['publishDate'],float):
                # e.g. "publishDate" : 1469544180,
                self.publishDate = str(p_alert_json['publishDate'])
            else:
                # e.g. "publishDate": "October 11, 2016 07:20:00 AM",
                logger.debug(p_alert_json['publishDate'])
                date_format = '%B %d, %Y %H:%M:%S %p'
                datetime_object = datetime.strptime(p_alert_json['publishDate'], date_format)
                import time
                timestamp = time.mktime(datetime_object.timetuple())
                self.publishDate = str(timestamp)

        if 'reportLink' in p_alert_json and p_alert_json['reportLink'] is not None:
            self.reportLink = str(p_alert_json['reportLink'])  # TYPE of APPLIANCE

        if 'emailIdentifier' in p_alert_json and p_alert_json['emailIdentifier'] is not None:
            self.emailIdentifier = str(p_alert_json['emailIdentifier'])

        if 'senderAddress' in p_alert_json and p_alert_json['senderAddress'] is not None:
            self.senderAddress = str(p_alert_json['senderAddress'])
        if 'senderName' in p_alert_json and p_alert_json['senderName'] is not None:
            self.senderName = str(p_alert_json['senderName'])
        if 'sourceDomain' in p_alert_json and p_alert_json['sourceDomain'] is not None:
            self.sourceDomain = str(p_alert_json['sourceDomain'])
        if 'sourceIp' in p_alert_json and p_alert_json['sourceIp'] is not None:
            self.sourceIp = str(p_alert_json['sourceIp'])
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
        if 'md5' in p_alert_json and p_alert_json['md5']is not None:
            self.md5 = str(p_alert_json['md5'])
        if 'sha1' in p_alert_json and p_alert_json['sha1']is not None:
            self.sha1 = str(p_alert_json['sha1'])

        if 'sha256' in p_alert_json and p_alert_json['sha256']is not None:
            self.sha256 = str(p_alert_json['sha256'])

        if 'description' in p_alert_json and p_alert_json['description']is not None:
            self.description = str(p_alert_json['description'])

        if 'fileType' in p_alert_json and p_alert_json['fileType']is not None:
            self.fileType = str(p_alert_json['fileType'])

        if 'packer' in p_alert_json and p_alert_json['packer']is not None:
            self.packer = str(p_alert_json['packer'])

        if 'userAgent' in p_alert_json and p_alert_json['userAgent']is not None:
            self.userAgent = str(p_alert_json['userAgent'])

        if 'registry' in p_alert_json and p_alert_json['registry']is not None:
            self.registry = str(p_alert_json['registry'])

        if 'fileCompilationDateTime' in p_alert_json and p_alert_json['fileCompilationDateTime']is not None:
            self.fileCompilationDateTime = str(p_alert_json['fileCompilationDateTime'])

        if 'filePath' in p_alert_json and p_alert_json['filePath']is not None:
            self.filePath = str(p_alert_json['filePath'])
        if 'asn' in p_alert_json and p_alert_json['asn']is not None:
            self.asn = str(p_alert_json['asn'])
        if 'cidr' in p_alert_json and p_alert_json['cidr']is not None:
            self.cidr = str(p_alert_json['cidr'])
        if 'domain' in p_alert_json and p_alert_json['domain']is not None:
            self.domain = str(p_alert_json['domain'])
        if 'domainTimeOfLookup' in p_alert_json and p_alert_json['domainTimeOfLookup']is not None:
            self.domainTimeOfLookup = str(p_alert_json['domainTimeOfLookup'])
        if 'networkIdentifier' in p_alert_json and p_alert_json['networkIdentifier']is not None:
            self.networkIdentifier = str(p_alert_json['networkIdentifier'])
        if 'ip' in p_alert_json and p_alert_json['ip']is not None:
            self.ip = str(p_alert_json['ip'])
        if 'port' in p_alert_json:
            self.port = str(p_alert_json['port'])
        if 'protocol' in p_alert_json:
            self.protocol = str(p_alert_json['protocol'])
        if 'registrantEmail' in p_alert_json:
            self.registrantEmail = str(p_alert_json['registrantEmail'])
        if 'registrantName' in p_alert_json:
            self.registrantName = str(p_alert_json['registrantName'])
        if 'networkType' in p_alert_json:
            self.networkType = str(p_alert_json['networkType'])
        if 'url' in p_alert_json and p_alert_json['url'] is not None:
            self.url = str(p_alert_json['url'])
        if 'malwareFamily' in p_alert_json:
            self.malwareFamily = str(p_alert_json['malwareFamily'])
        if 'malwareFamilyId' in p_alert_json:
            self.malwareFamilyId = str(p_alert_json['malwareFamilyId'])
        if 'actor' in p_alert_json and p_alert_json['actor'] is not None:
            self.actor = str(p_alert_json['actor'])
        if 'actorId' in p_alert_json:
            self.actorId = str(p_alert_json['actorId'])
        if 'observationTime' in p_alert_json:
            self.observationTime = str(p_alert_json['observationTime'])
        if 'riskRating' in p_alert_json:
            self.riskRating = str(p_alert_json['riskRating'])
        if 'registryHive' in p_alert_json:
            self.registryHive = str(p_alert_json['registryHive'])
        if 'registryKey' in p_alert_json:
            self.registryKey = str(p_alert_json['registryKey'])
        if 'registryValue' in p_alert_json:
            self.registryValue = str(p_alert_json['registryValue'])
        if 'title' in p_alert_json:
            self.title = str(p_alert_json['title'])

        logger.debug("Parsing finished")

