#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Created on Sep 20, 2016

@author: deralexxx

Script to pull iocs from iSight and push it to MISP

Alexander Jaeger

See CHANGELOG.md for history

"""

import email.utils
import hashlib
import hmac
import json
import sys
import threading
import time
import urllib.parse

from urllib3 import ProxyManager
import urllib3

import PySight_settings
from model.pySightReport import pySightReport

try:
    from pymisp import PyMISP, MISPEvent, MISPObject

    HAVE_PYMISP = True
except Exception as e:
    HAVE_PYMISP = False

urllib3.disable_warnings()

# read the config file

start_time = time.time()
threadLimiter = threading.BoundedSemaphore(1)


# some helper methods


def get_misp_instance():
    """

    :return: MISP Instance
    :rtype: PyMISP
    """
    try:
        if not HAVE_PYMISP:
            PySight_settings.logger.error("Missing dependency, install pymisp (`pip install pymisp`)")
            return False
        else:
            # PyMISP.proxies
            return PyMISP(PySight_settings.misp_url, PySight_settings.misp_key, PySight_settings.misp_verifycert,
                          proxies=None)
    except Exception:
        PySight_settings.logger.error("Unexpected error in MISP init: %s", sys.exc_info())
        return False


def misp_delete_events(a_start, a_end, a_misp_instance):
    """

    :param a_start:
    :type a_start:
    :param a_end:
    :type a_end:
    :param a_misp_instance:
    :type a_misp_instance:
    :return:
    :rtype:
    """
    print(a_start)
    print(a_end)

    try:
        for i in range(a_start, a_end, 1):
            print(i)
            a_misp_instance.delete_event(i)
        return True
    except TypeError as e:
        print("TypeError error: %s", e.message)
        return False
    except Exception:
        print("Unexpected error: %s", sys.exc_info())
        return True


def check_misp_all_result(a_result):
    """
    :param a_result:
    :type a_result:
    :return: previous event from MISP
    :rtype:
    """
    # PySight_settings.logger.debug("Checking %s if it contains previous events", a_result)
    if 'message' in a_result:
        if a_result['message'] == 'No matches.':
            PySight_settings.logger.error("No previous event found")
            # has really no event
            return False
    elif 'Event' in a_result:
        for e in a_result['response']:
            PySight_settings.logger.debug("found a previous event!")
            previous_event = e['Event']['id']
            return previous_event
            break
    else:
        for e in a_result['response']:
            PySight_settings.logger.debug("found a previous event!")
            previous_event = e['Event']['id']
            return previous_event
            break


# INIT iSight Stuff

def get_headers(a_prv, a_pub, a_query):
    """

    :param a_prv:
    :type a_prv:
    :param a_pub:
    :type a_pub:
    :param a_query:
    :type a_query:
    :return: headers for iSight search
    :rtype:
    """
    time_stamp = email.utils.formatdate(localtime=True)

    new_data = a_query + '2.4' + 'application/json' + time_stamp
    # new_data=''
    # TODO: that is currently broken! TypeError: string argument without an encoding
    message = bytes(new_data, 'utf-8')
    secret = bytes(a_prv, 'utf-8')

    # hashed = hmac.new(bytearray(a_prv,'utf8'), new_data, hashlib.sha256)
    hashed = hmac.new(secret, message, hashlib.sha256)
    headers = {
        'Accept': 'application/json',
        'Accept-Version': '2.4',
        'X-Auth': a_pub,
        'X-Auth-Hash': hashed.hexdigest(),
        'Date': time_stamp
    }
    return headers


def isight_prepare_data_request(a_url, a_query, a_pub_key, a_prv_key):
    """

    :param a_url:
    :type a_url:
    :param a_query:
    :type a_query:
    :param a_pub_key:
    :type a_pub_key:
    :param a_prv_key:
    :type a_prv_key:
    :return:
    :rtype:
    """
    headers = get_headers(a_prv_key, a_pub_key, a_query)
    result = isight_load_data(a_url, a_query, headers)

    if not result:
        PySight_settings.logger.error("Something went wrong while downloading / processing the iSight Request")
        return False
    else:
        return result


def isight_load_data(a_url, a_query, a_headers):
    """

    :param a_url:
    :type a_url:
    :param a_query:
    :type a_query:
    :param a_headers:
    :type a_headers:
    :return:
    :rtype:
    """
    try:
        PySight_settings.logger.debug("param headers: %s %s", a_headers, a_url)
        proxy_request = ProxyManager(str(PySight_settings.proxy_adress))
        url_to_load = PySight_settings.isight_url + a_query
        PySight_settings.logger.debug(url_to_load)
        try:

            r = proxy_request.request('GET', a_url + a_query, None, headers=a_headers)
        except urllib.error.HTTPError as e:
            print(e.code)
            print(e.read())

        PySight_settings.logger.debug("headers %s: ", proxy_request.headers)

        PySight_settings.logger.debug("data %s: ", r.data)

        return_data_cleaned = r.data.replace('\n', '')
        # return_data_cleaned =

        json_return_data_cleaned = json.loads(return_data_cleaned.decode('utf8'))
        PySight_settings.logger.debug(json_return_data_cleaned)

        # print json.dumps(theJson,sort_keys=True,indent = 4, separators = (',', ': '))
        PySight_settings.logger.debug("Number of iocs: %s answer is: %s", len(json_return_data_cleaned['message']),
                                      json_return_data_cleaned)

        if not json_return_data_cleaned['success']:
            PySight_settings.logger.error("Error with iSight connection %s",
                                          json_return_data_cleaned['message']['description'])
            PySight_settings.logger.error(json_return_data_cleaned)
            return False
        else:
            import time
            timestring = time.strftime("%Y%m%d-%H%M%S")
            f = open("debug/" + timestring, 'w')
            f.write(json.dumps(json_return_data_cleaned, sort_keys=True, indent=6, separators=(',', ': ')))
            f.close()

            return json_return_data_cleaned
    except Exception:
        print("Unexpected error: %s", sys.exc_info())
        return False


def isight_process_alert_content_element(a_json):
    """
    create pySightAlert Instance of the json and makes all the mapping

    :param a_json:
    :type a_json:
    """

    try:
        import json
        # get a misp instance per threat
        this_misp_instance = get_misp_instance()

        # without a MISP instance this does not make sense
        if this_misp_instance is False:
            raise "no MISP instance found"

        threadLimiter.acquire()

        # logger.debug("max number %s current number: ", threadLimiter._initial_value, )
        # logger.debug(p_json)
        # write it to file
        # parsing of json to the pySightReport
        isight_report_instance = pySightReport(a_json)
        # This comment will be added to every attribute for reference
        auto_comment = "pySightMisp " + (isight_report_instance.reportId)

        f = open("reports/" + isight_report_instance.reportId, 'a')
        f.write(json.dumps(a_json, sort_keys=True, indent=4, separators=(',', ': ')))
        f.close()

        # create a MISP event FIXME: Not used
        # has_previous_event = True

        PySight_settings.logger.debug("checking for previous events with report ID %s", isight_report_instance.reportId)
        event = misp_check_for_previous_events(this_misp_instance, isight_report_instance)

        if not event:
            PySight_settings.logger.error("no event! need to create a new one")
        else:
            # ataching the data to the previously found event
            if not is_map_alert_to_event(this_misp_instance, event, isight_report_instance, auto_comment):
                PySight_settings.logger.error("Something went wrong with event mapping")

        # reset the instance afterwards
        isight_report_instance = None

        # release the limiter
        threadLimiter.release()

    except AttributeError as e:
        sys, traceback = error_handling(e, a_string="Attribute Error")
        return False
    except TypeError as e:
        sys, traceback = error_handling(e, a_string="Type Error:")
        return False
    except Exception as e:
        sys, traceback = error_handling(e, a_string="General Error:")
        return False


def error_handling(e, a_string):
    """

    :param e:
    :type e:
    :param a_string:
    :type a_string:
    :return:
    :rtype:
    """
    if hasattr(e, 'message'):
        PySight_settings.logger.error("%s %s", a_string, e.message)
    import sys
    import traceback
    PySight_settings.logger.debug('1 %s', e.__doc__)
    PySight_settings.logger.debug('2 %s', sys.exc_info())
    PySight_settings.logger.debug('3 %s', sys.exc_info()[0])
    PySight_settings.logger.debug('4 %s', sys.exc_info()[1])
    # PySight_settings.logger.debug('5 %s', sys.exc_info()[2], 'Sorry I mean line...', traceback.tb_lineno(sys.exc_info()[2]))
    ex_type, ex, tb = sys.exc_info()
    PySight_settings.logger.debug('6 %s', traceback.print_tb(tb))
    return sys, traceback


def is_map_alert_to_event(p_misp_instance, new_misp_event, a_isight_alert, a_auto_comment):
    """

    START THE MAPPING here
    general info that should be there in every alert
    internal reference the alert ID

    :return True if maping worked
            False if an error occured
    :rtype: Boolean
    :param p_misp_instance:
    :type pyMisp:
    :param a_auto_comment:
    :type a_auto_comment:
    :param a_event:
    :type a_event:
    :param a_isight_alert:
    :type a_isight_alert:
    """

    try:
        if not isinstance(p_misp_instance, PyMISP):
            # if this is not the right type
            PySight_settings.logger.error("Parameter misp instance is not an PyMisp object")
            return False

        PySight_settings.logger.debug("mapping alert %s", a_isight_alert.reportId)
        new_misp_event.add_attribute(type='other', value=a_isight_alert.reportId, comment=a_auto_comment, category='Internal reference')

        # Start Tagging here
        # this Tag migth be custom, that is why it will be created:
        p_misp_instance.new_tag('iSight', exportable=True)  # FIXME: Don't do that for each event.
        new_misp_event.add_tag('iSight')

        # TLP change it if you want to change default TLP
        new_misp_event.add_tag('tlp:amber')

        # General detected by a security system. So reflect in a tag
        new_misp_event.add_tag('veris:discovery_method="Prt - monitoring service"')
        # Severity Tag + Threat level of the Event
        if a_isight_alert.riskRating:
            PySight_settings.logger.debug("risk: %s", a_isight_alert.riskRating)
            if a_isight_alert.riskRating == 'High':
                new_misp_event.add_tag('csirt_case_classification:criticality-classification="1"')
                # upgrade Threat level if set already
                new_misp_event.threat_level_id = 1
            elif a_isight_alert.alert_severity == 'minr':
                new_misp_event.add_tag('csirt_case_classification:criticality-classification="3"')
                new_misp_event.add_tag('veris:impact:overall_rating = "Insignificant"')
                new_misp_event.threat_level_id = 3
            else:
                new_misp_event.add_tag('csirt_case_classification:criticality-classification="3"')
                new_misp_event.add_tag('veris:impact:overall_rating = "Unknown"')
                new_misp_event.threat_level_id = 4
        else:
            PySight_settings.logger.info("No Event severity found")

        if a_isight_alert.ThreatScape:
            if a_isight_alert.ThreatScape == 'Espionage' or a_isight_alert.ThreatScape == 'cyberEspionage':
                new_misp_event.add_tag('veris:actor:motive="Espionage"')
            elif a_isight_alert.ThreatScape == 'hacktivism':
                new_misp_event.add_tag('veris:actor:external:variety="Activist"')
            elif a_isight_alert.ThreatScape == 'cyberCrime' or a_isight_alert.ThreatScape == 'Cyber Crime':
                new_misp_event.add_tag('veris:actor:external:variety="Organized crime"')

        # Add tag if APT is in the title:
        if "APT" in a_isight_alert.title:
            new_misp_event.add_tag('APT')
            new_misp_event.add_tag('Threat Type="APT"')

        # Url of the original Alert
        if a_isight_alert.reportLink:
            new_misp_event.add_attribute(type='link', value=a_isight_alert.reportLink, to_ids=False, comment="reportLink: {}".format(a_auto_comment))

        # File infos
        if a_isight_alert.md5:
            PySight_settings.logger.debug("Malware within the event %s", a_isight_alert.md5)
            new_file_object = MISPObject(name='file', standalone=False)
            new_file_object.add_attribute('filename', a_isight_alert.fileName, to_ids=False)
            new_file_object.add_attribute('md5', a_isight_alert.md5, to_ids=False)
            new_file_object.add_attribute('sha1', a_isight_alert.sha1, to_ids=False)
            new_file_object.add_attribute('sha256', a_isight_alert.sha256, to_ids=False)
            if not (a_isight_alert.description is None):
                new_file_object.comment = '{} Name of file {}'.format(a_auto_comment, a_isight_alert.description)
            else:
                new_file_object.comment = '{} Name of file'.format(a_auto_comment)
            new_misp_event.add_object(new_file_object)

        # if not (iSight_alert.fileSize is None):
        #        misp_instance.add_internal_text(event, iSight_alert.fileSize, False, auto_comment + "  File size in bytes")
        if not (a_isight_alert.fuzzyHash is None):
            # FIXME: probably better to attach to an existing MISPObject of type file
            new_misp_event.add_attribute(type='text', value=a_isight_alert.fuzzyHash, category='Internal reference', comment=a_auto_comment + "{} File fuzzy (ssdeep) hash".format(a_auto_comment))

        if a_isight_alert.fileIdentifier and a_isight_alert.fileIdentifier is not None:
            desc = ""
            if a_isight_alert.fileIdentifier == "Attacker":
                desc = "Indicators confirmed to host malicious content, has functioned as a commandand-control (C2) server, and/or otherwise acted as a source of malicious activity."
            elif a_isight_alert.fileIdentifier == "Compromised":
                desc = "Indicators confirmed to host malicious content due to compromise or abuse. The exact time and length of compromise is unknown unless disclosed within the report."

            elif a_isight_alert.fileIdentifier == "Related":
                desc = 'Indicators likely related to an attack but potentially only partially confirmed. Detailed by one or more methods, like passive DNS, geo-location, and connectivity detection.'
            elif a_isight_alert.fileIdentifier == "Victim":
                desc = "Indicators representing an entity that has been confirmed to have been victimized by malicious activity, where actors have attempted or succeeded to compromise."

            new_misp_event.add_attribute(type='other', value=a_isight_alert.fileIdentifier, category='Internal reference', comment="{} File characterization {}".format(a_auto_comment, desc))

        desc = ""

        for network in a_isight_alert.networks_array:
            if network.networkType == "C&C":
                desc = "Indicators confirmed to host malicious content, has functioned as a commandand-control (C2) server, and/or otherwise acted as a source of malicious activity."
                PySight_settings.logger.debug("Network indicator found")
                attribute = new_misp_event.add_attribute(type='domain', value=network.domain, comment='{} domain {}'.format(desc, a_auto_comment))
                attribute.add_tag('veris:action:malware:variety="C2"')

                # p_misp_instance.add_tag()
                PySight_settings.logger.error("added " + network.domain)

                # for temp in result_attribute['Event']['Attribute']:
                #    attribute_id = temp
                #    break
                # TODO: that needs to be reviewed
                # TODO: make it a config value what to do with C2, PAP X Y Z
                # p_misp_instance.add_tag(attribute_id, "PAP:WHITE", attribute=True)

        if a_isight_alert.networkIdentifier and a_isight_alert.networkIdentifier is not None:
            desc = ""
            if a_isight_alert.networkIdentifier == "Attacker":
                # TODO: Then something is C2?!
                a_isight_alert.isCommandAndControl = True
                desc = "Indicators confirmed to host malicious content, has functioned as a commandand-control (C2) server, and/or otherwise acted as a source of malicious activity."
            elif a_isight_alert.networkIdentifier == "Compromised":
                desc = "Indicators confirmed to host malicious content due to compromise or abuse. The exact time and length of compromise is unknown unless disclosed within the report."

            elif a_isight_alert.networkIdentifier == "Related":
                desc = 'Indicators likely related to an attack but potentially only partially confirmed. Detailed by one or more methods, like passive DNS, geo-location, and connectivity detection.'
            elif a_isight_alert.networkIdentifier == "Victim":
                desc = "Indicators representing an entity that has been confirmed to have been victimized by malicious activity, where actors have attempted or succeeded to compromise."

        if a_isight_alert.fileType:
            new_misp_event.add_attribute(type='other', value=a_isight_alert.fileType, category='Internal reference', comment="{} File format".format(a_auto_comment))

        if a_isight_alert.packer:
            new_misp_event.add_attribute(type='other', value=a_isight_alert.packer, category='Internal reference', comment="{} Packer used on file".format(a_auto_comment))
        if a_isight_alert.registryHive:
            new_misp_event.add_attribute(type='other', value=a_isight_alert.registryHive, category='Internal reference', comment="{} Hive value of registry used".format(a_auto_comment))
        if a_isight_alert.registryKey:
            new_misp_event.add_attribute(type='other', value=a_isight_alert.registryKey, category='Internal reference', comment="{} Key of registry used".format(a_auto_comment))
        if a_isight_alert.registryValue:
            new_misp_event.add_attribute(type='other', value=a_isight_alert.registryValue, category='Internal reference', comment="{} Value of registry key used".format(a_auto_comment))

        # Threat Actor
        if a_isight_alert.actorId and a_isight_alert.actorId is not None and a_isight_alert.actorId != 'None':
            new_misp_event.add_attribute(type='threat-actor', value=a_isight_alert.actorId, comment=a_auto_comment)

        if a_isight_alert.actor and a_isight_alert.actor is not None:
            new_misp_event.add_attribute(type='threat-actor', value=a_isight_alert.actor, comment=a_auto_comment)

        # Domain
        if a_isight_alert.domain:
            PySight_settings.logger.debug("Network indicator found")
            new_attribute = new_misp_event.add_attribute(type='domain', value=a_isight_alert.domain, comment='{} domain {}'.format(desc, a_auto_comment))
            # TODO: that needs to be reviewed
            # TODO: make it a config value what to do with C2, PAP X Y Z
            new_attribute.add_tag('PAP:WHITE')
            # TODO: Add custom Tag if that is C2 as soon as https://github.com/MISP/MISP/issues/802 is completed
        if a_isight_alert.ip:
            PySight_settings.logger.debug("IP indicator found")
            # TODO Activcate that again maybe?!
            # data_basic_search_ip(PySight_settings.isight_url, PySight_settings.isight_pub_key, PySight_settings.isight_priv_key, a_isight_alert.ip)
            # TODO: Add custom Tag if that is C2 as soon as https://github.com/MISP/MISP/issues/802 is completed
            new_misp_event.add_attribute(type='ip-dst', value=a_isight_alert.ip, comment='{} ip {}'.format(desc, a_auto_comment))

        if a_isight_alert.isCommandAndControl:
            new_misp_event.add_tag('veris:action:malware:variety="C2"')

        if not (a_isight_alert.url is None):
            new_misp_event.add_attribute(type='url', value=a_isight_alert.url, comment='url {}'.format(a_auto_comment))

        has_email = False
        new_email_object = MISPObject(name='email', standalone=False)
        # if attack was by E-Mail
        if a_isight_alert.senderAddress:
            new_email_object.add_attribute('from', value=a_isight_alert.senderAddress, to_ids=False, comment='senderAddress {}'.format(a_auto_comment))
            has_email = True
        if a_isight_alert.subject:
            new_email_object.add_attribute('subject', value=a_isight_alert.subject, to_ids=False, comment='E-mail subject {}'.format(a_auto_comment))
            has_email = True
        if a_isight_alert.senderName:
            new_email_object.add_attribute('from-display-name', value=a_isight_alert.senderName, to_ids=False, comment='E-mail sender name {}'.format(a_auto_comment))
            has_email = True
        if a_isight_alert.sourceDomain:
            attr = new_misp_event.add_attribute(type='domain', value=a_isight_alert.sourceDomain, comment='E-mail source domain {}'.format(a_auto_comment))
            if has_email:
                new_email_object.add_reference(attr.uuid, 'related-to', 'E-mail source domain')
        if a_isight_alert.emailLanguage:
            attr = new_misp_event.add_attribute(type='other', value=a_isight_alert.emailLanguage, category='Internal reference', comment='E-mail language {}'.format(a_auto_comment))
            if has_email:
                new_email_object.add_reference(attr.uuid, 'related-to', 'E-mail language')
        if has_email:
            new_misp_event.add_object(new_email_object)
        p_misp_instance.add_event(new_misp_event)
    except TypeError:
        # sys, traceback = error_handling(e,a_string="Type Error")
        import sys
        PySight_settings.logger.error("TypeError error: %s", sys.exc_info[0])
        return False
    except AttributeError:
        # sys, traceback = error_handling(e,a_string="Attribute Error")
        import sys
        PySight_settings.logger.error("Attribute Error %s", sys.exc_info()[0])
    except Exception:
        import sys
        PySight_settings.logger.error("General Error %s", sys.exc_info()[0])
        return False

    return True


def misp_check_for_previous_events(misp_instance, isight_alert):
    """
    Default: no previous event detected


    check for:
        alert_id | ['alert']['id']

    :param misp_instance:
    :type misp_instance:
    :param isight_alert:
    :type isight_alert:
    :return:
        event id if an event is there
        false if no event is present
    :rtype:
    """
    event = False

    if misp_instance is None:
        PySight_settings.logger.error("No misp instance given")
        return False

    # Based on alert id
    if isight_alert.reportId:
        result = misp_instance.search_all(isight_alert.reportId)
        PySight_settings.logger.debug("searched in MISP for %s result: %s", isight_alert.reportId, result)
        event = check_misp_all_result(result)

    # Based on Alert Url
    if isight_alert.reportLink and not event:
        from urllib import quote

        result = misp_instance.search_all(quote(isight_alert.reportLink))
        PySight_settings.logger.debug("searching in MISP for %s result: %s", isight_alert.reportLink, result)

        event = check_misp_all_result(result)

    # if one of the above returns a value:
    previous_event = event
    # this looks hacky but it to avoid exceptions if there is no ['message within the result']

    if previous_event is not '' and previous_event is not False and previous_event is not None:
        PySight_settings.logger.debug("Will append my data to: %s", previous_event)
        event = misp_instance.get(str(previous_event))  # not get_event!
    else:
        PySight_settings.logger.debug("Will create a new event for it")
        event = MISPEvent()

        if isight_alert.publishDate:
            new_date = time.strftime('%Y-%m-%d', time.localtime(float(isight_alert.publishDate)))
            PySight_settings.logger.debug("Date will be %s title: %s ID %s", new_date, isight_alert.title,
                                          isight_alert.reportId)
            try:
                event.distribution = 0
                event.threat_level_id = 2
                event.analysis = 0
                event.info = isight_alert.title + " pySightSight " + isight_alert.reportId
                event.set_date(new_date)
            except Exception:
                import sys
                print("Unexpected error:", sys.exc_info()[0])
        else:
            event.distribution = 0
            event.threat_level_id = 2
            event.analysis = 0
            event.info = isight_alert.title + " pySightSight " + isight_alert.reportId

    if not event:
        PySight_settings.logger.error("Something went really wrong")
        event.distribution = 0
        event.threat_level_id = 2
        event.analysis = 0
        event.info = isight_alert.title + " pySightSight " + isight_alert.reportId
    return event


def data_text_search_title(url, public_key, private_key):
    print("text_search_title Response:")
    # title phrase search
    params = {
        'text': 'title:"Software Stack 3.1.2"'
    }
    text_search_query = '/search/text?' + urllib.urlencode(params)
    isight_prepare_data_request(url, text_search_query, public_key, private_key)


def data_text_search_wildcard(url, public_key, private_key):
    print("text_search_wildcard Response:")
    # wild card text search
    params = {
        'text': 'zero-day*',
        'limit': '10',
        'offset': '0'
    }
    text_search_query = '/search/text?' + urllib.urlencode(params)
    isight_prepare_data_request(url, text_search_query, public_key, private_key)


def data_search_report(url, public_key, private_key, a_reportid):
    print("text_search_wildcard Response:")
    # wild card text search
    # FIXME: not used
    # params = {
    #    'reportID': a_reportid
    # }
    text_search_query = '/report/' + a_reportid
    isight_prepare_data_request(url, text_search_query, public_key, private_key)


def data_text_search_sensitive_reports(url, public_key, private_key):
    print("text_search_sensitive_reports Response:")
    params = {
        'text': 'title:"Latin American"',
        'customerIntelOnly': True
    }
    text_search_query = '/search/text?' + urllib.urlencode(params)
    isight_prepare_data_request(url, text_search_query, public_key, private_key)


def data_search_indicators_last24_h(url, public_key, private_key):
    hours = PySight_settings.isight_last_hours
    since = int(time.time()) - hours * 60 * 60
    return data_search_indicators_since(private_key, public_key, url, since)


def data_search_indicators_since(private_key, public_key, url, since):
    print("text_search_sensitive_reports Response:")
    # since = int(time.time()) - hours * 60 * 60

    params = {
        'since': since
    }
    text_search_query = '/view/indicators?' + urllib.parse.urlencode(params)
    return isight_prepare_data_request(url, text_search_query, public_key, private_key)


def data_advanced_search_filter_indicators(url, public_key, private_key):
    print("advanced_search_filter_indicators Response:")
    # Indicator field md5
    advanced_search_query = '/search/advanced?query=md5=~8512835a95d0fabfb&fileIdentifier=[Victim;Attacker]'
    isight_prepare_data_request(url, advanced_search_query, public_key, private_key)


def data_basic_search_ip(url, public_key, private_key, ip):
    PySight_settings.logger.debug("basic_search Response")
    # Query for search
    basic_search_query = '/search/basic?ip=' + ip
    isight_prepare_data_request(url, basic_search_query, public_key, private_key)


def data_ioc(url, public_key, private_key):
    # print ("iocs Response:")
    # 30 days back start date
    startDate = int(time.time()) - 2592000
    endDate = int(time.time())
    ioc_query = '/view/iocs?' + 'startDate=' + str(startDate) + '&endDate=' + str(endDate)
    return isight_prepare_data_request(url, ioc_query, public_key, private_key)


def data_text_search_simple(url, public_key, private_key):
    print("text_search_simple Response:")
    # simple text search
    params = {
        'text': 'Stack-Based Buffer Overflow Vulnerability',
        'limit': '10',
        'offset': '0'
    }
    text_search_query = '/search/text?' + urllib.urlencode(params)
    isight_prepare_data_request(url, text_search_query, public_key, private_key)


def data_text_search_filter(url, public_key, private_key):
    try:
        print("text_search_filter Response:")
        # filter text search
        params = {
            'text': 'malware',
            'filter': 'threatScape:cyberEspionage,cyberCrime&riskRating:HIGH,LOW&language:english',
            'sortBy': 'title:asc,reportId:desc',
            'limit': '10',
            'offset': '5'
        }
        text_search_query = '/search/text?' + urllib.urlencode(params)
        print('text_search_query', text_search_query)
        isight_prepare_data_request(url, text_search_query, public_key, private_key)

        params = {
            'text': 'malware',
            'filter': 'cveId:~\'CVE\''

        }
        text_search_query = '/search/text?' + urllib.urlencode(params)
        return isight_prepare_data_request(url, text_search_query, public_key, private_key)
    except Exception:
        return False


def data_test(url, public_key, private_key):
    PySight_settings.logger.debug("test the api:")
    # title phrase search
    text_search_query = '/test'
    isight_prepare_data_request(url, text_search_query, public_key, private_key)


def test_isight_connection():
    result = data_test(PySight_settings.isight_url, PySight_settings.isight_pub_key, PySight_settings.isight_priv_key)
    if not result:
        return False
    else:
        PySight_settings.logger.debug("else %s", result)
        return True

        # Returns an intelligence report in a specific format and at a specific level of detail.


def misp_process_isight_alert(a_result):
    """

    :param a_result:
    :type a_result:
    """

    global end
    for i in a_result['message']:
        PySight_settings.logger.debug("  %s current element %s", len(a_result['message']), i)

        # USING THREADS to proceed with the resulting JSON
        if PySight_settings.use_threading:
            t = threading.Thread(target=isight_process_alert_content_element, args=(i,))
            t.start()
        else:
            # NO THREADING

            isight_process_alert_content_element(i)
            PySight_settings.logger.debug("Sleeping for %s seconds", PySight_settings.time_sleep)
            time.sleep(PySight_settings.time_sleep)
    end = timer()


if __name__ == '__main__':
    misp_instance = get_misp_instance()

    # TODO: not yet finished to parse the report!
    # data_search_report(isight_url, public_key, private_key, "16-00014614")

    # this is to log the time used to run the script
    from timeit import default_timer as timer

    start = timer()
    result = data_search_indicators_last24_h(PySight_settings.isight_url, PySight_settings.isight_pub_key,
                                             PySight_settings.isight_priv_key)

    misp_process_isight_alert(result)

    print("Time taken %s", end - start)

    # data_test(isight_url,public_key,private_key)
    #
    # data_ioc(url, public_key, private_key)
    # data_text_search_simple(isight_url, public_key, private_key)
    # data_text_search_filter(isight_url, public_key, private_key)
    # data_text_search_title(url, public_key, private_key)
    # data_text_search_wildcard(url, public_key, private_key)
    # data_text_search_sensitive_reports(isight_url, public_key, private_key)
    # data_advanced_search_filter_indicators(url, public_key, private_key)
