#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Created on Sep 20, 2016

@author: deralexxx

Script to pull iocs from iSight and push them to MISP

Alexander Jaeger

See CHANGELOG.md for history
"""

import datetime
import email.utils
import hashlib
import hmac
import json
import os
from pymisp import ExpandedPyMISP, MISPEvent, MISPObject
#from pymisp import PyMISP, MISPEvent, MISPObject
import requests
import sys
import threading
import time
import urllib.parse
import urllib3

# Read the config file.
import PySight_settings

# Import our own iSight report model.
from model.pySightReport import pySightReport

# Suppress insecure HTTPS request warnings.
urllib3.disable_warnings()


# Error handling function.
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
        PySight_settings.logger.error('%s %s', a_string, e.message)
    import traceback
    PySight_settings.logger.debug('1 %s', e.__doc__)
    PySight_settings.logger.debug('2 %s', sys.exc_info())
    PySight_settings.logger.debug('3 %s', sys.exc_info()[0])
    PySight_settings.logger.debug('4 %s', sys.exc_info()[1])
    #PySight_settings.logger.debug('5 %s', sys.exc_info()[2], 'Sorry I mean line...',
    #                              traceback.tb_lineno(sys.exc_info()[2]))
    ex_type, ex, tb = sys.exc_info()
    PySight_settings.logger.debug('6 %s', traceback.print_tb(tb))
    return sys, traceback


# This function is not used!
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


# Update an existing MISP event.
def update_misp_event(misp_instance, event, isight_alert):
    # Update attributes based on the iSight report.
    #
    # Ideas of Alex not implemented:
    # Use expanded networkIdentifier as a comment.
    # Create attributes and use object relationships for iSight fields that have no corresponding MISP object attribute.
    #
    # Unused iSight fields: observationTime

    PySight_settings.logger.debug('Updating the event %s', event)

    # Verify that misp_instance is of the correct type
    #if not isinstance(misp_instance, PyMISP):
    if not isinstance(misp_instance, ExpandedPyMISP):
        PySight_settings.logger.error('Parameter misp_instance is not a PyMISP object')
        return False

    # Determine whether the to_ids flag shall be set.
    if isight_alert.emailIdentifier == 'Attacker' or isight_alert.emailIdentifier == 'Compromised':
        email_ids = True
    else:
        email_ids = False
    if isight_alert.fileIdentifier == 'Attacker' or isight_alert.fileIdentifier == 'Compromised':
        file_ids = True
    elif isight_alert.intelligenceType == 'malware':
        file_ids = True
    else:
        file_ids = False
    if isight_alert.networkIdentifier == 'Attacker' or isight_alert.networkIdentifier == 'Compromised':
        network_ids = True
    else:
        network_ids = False

    # Use malwareFamily as the default comment.
    if isight_alert.malwareFamily:
        default_comment = isight_alert.malwareFamily
    else:
        default_comment = ''

    # If the alert contains email indicators, create an email object.
    if isight_alert.emailIdentifier:
        # If emailLanguage is provided, add it to the default comment.
        if isight_alert.emailLanguage:
            add_comment = 'Email language: ' + isight_alert.emailLanguage
            if default_comment == '':
                email_comment = add_comment
            else:
                email_comment = default_comment + '; ' + add_comment
        else:
            email_comment = default_comment
        # Create the object.
        email_object = MISPObject('email')
        email_object.comment = email_comment
        # Add attributes to the object.
        if isight_alert.senderAddress:
            email_object.add_attribute('from', value=isight_alert.senderAddress, to_ids=email_ids)
        if isight_alert.senderName:
            email_object.add_attribute('from-display-name', value=isight_alert.senderName, to_ids=False)
        if isight_alert.sourceIP:
            email_object.add_attribute('ip-src', value=isight_alert.sourceIP, to_ids=email_ids)
        if isight_alert.subject:
            email_object.add_attribute('subject', value=isight_alert.subject, to_ids=False)
        if isight_alert.recipient:
            email_object.add_attribute('to', value=isight_alert.recipient, to_ids=False)
        if isight_alert.senderDomain:
            domain_attribute = event.add_attribute(category='Network activity', type='domain',
                                                   value=isight_alert.senderDomain, to_ids=False)
            email_object.add_reference(domain_attribute.uuid, 'derived-from', comment='Email source domain')
        # Lastly, add the object to the event.
        event.add_object(email_object)

    # If the report contains an MD5 hash, create a file object.
    if isight_alert.md5:
        # If a file description is given, add it to the default comment.
        if isight_alert.description:
            add_comment = isight_alert.description
            if default_comment == '':
                file_comment = add_comment
            else:
                file_comment = default_comment + '; ' + add_comment
        else:
            file_comment = default_comment
        # Create the object.
        file_object = MISPObject('file')
        file_object.comment = file_comment
        # Add attributes to the object.
        file_object.add_attribute('md5', value=isight_alert.md5, to_ids=file_ids)
        if isight_alert.sha1:
            file_object.add_attribute('sha1', value=isight_alert.sha1, to_ids=file_ids)
        if isight_alert.sha256:
            file_object.add_attribute('sha256', value=isight_alert.sha256, to_ids=file_ids)
        if isight_alert.fileName and not isight_alert.fileName == 'UNAVAILABLE' and \
                not isight_alert.fileName.upper() == 'UNKNOWN':
            # Don't use filenames for detection.
            file_object.add_attribute('filename', value=isight_alert.fileName, to_ids=False)
        if isight_alert.fileSize:
            # Don't use file size for detection.
            file_object.add_attribute('size-in-bytes', value=isight_alert.fileSize, to_ids=False)
        if isight_alert.fuzzyHash:
            file_object.add_attribute('ssdeep', value=isight_alert.fuzzyHash, to_ids=file_ids)
        if isight_alert.fileType and not isight_alert.fileType == 'fileType':
            # Don't use file type for detection.
            file_object.add_attribute('text', value=isight_alert.fileType, to_ids=False)
        if isight_alert.fileCompilationDateTime:
            # Convert epoch format to ISO86011 UTC format.
            compile_date = datetime.datetime.fromtimestamp(isight_alert.fileCompilationDateTime)
            file_object.add_attribute('compilation-timestamp', value=str(compile_date), to_ids=False)
        if isight_alert.filePath:
            file_object.add_attribute('path', value=isight_alert.filePath, to_ids=False)
        # Lastly, add the object to the event.
        event.add_object(file_object)

    # If the report contains a user agent string, create a user-agent attribute.
    if isight_alert.userAgent:
        event.add_attribute(category='Network activity', type='user-agent', value=isight_alert.userAgent,
                            to_ids=network_ids, comment=default_comment)

    # If the report contains an ASN, create an AS attribute.
    if isight_alert.asn:
        # Don't use the ASN for detection.
        event.add_attribute(category='Network activity', type='AS', value=isight_alert.asn, to_ids=False,
                            comment=default_comment)

    # If the report contains a domain, create a hostname attribute (because iSight domain names are in fact hostnames).
    if isight_alert.domain:
        # If an IP address is provided with a hostname, put the IP address in a comment, possibly in addition to the
        # default network comment.
        if isight_alert.ip:
            add_comment = 'Resolves to ' + isight_alert.ip
            if default_comment == '':
                temp_comment = add_comment
            else:
                temp_comment = default_comment + '; ' + add_comment
        else:
            temp_comment = default_comment
        # If a protocol is provided, also add it to the comment.
        if isight_alert.protocol:
            add_comment = isight_alert.protocol
            if temp_comment == '':
                host_comment = add_comment
            else:
                host_comment = temp_comment + '; ' + add_comment
        else:
            host_comment = temp_comment
        # Add the attribute to the event. If a port is provided, use a combined attribute.
        if isight_alert.port:
            host_port = isight_alert.domain + '|' + isight_alert.port
            new_attr = event.add_attribute(category='Network activity', type='hostname|port', value=host_port,
                                           to_ids=network_ids, comment=host_comment)
        else:
            new_attr = event.add_attribute(category='Network activity', type='hostname', value=isight_alert.domain,
                                           to_ids=network_ids, comment=host_comment)
        if isight_alert.networkType == 'C&C':
            # Add veris tag to attribute.
            new_attr.add_tag('veris:action:malware:variety="C2"')
    # If the report doesn't contain a hostname but contains an IP address, create an ip-src or ip-dst attribute.
    # TODO: Is there a better way to determine whether it's a source or destination IP address?
    elif isight_alert.ip:
        # Add the protocol to the comment if it is provided by iSight.
        if isight_alert.protocol:
            add_comment = isight_alert.protocol
            if default_comment == '':
                ip_comment = add_comment
            else:
                ip_comment = default_comment + '; ' + add_comment
        else:
            ip_comment = default_comment
        if isight_alert.networkIdentifier == 'Attacker':
            # Might be source or destination, but likelihood of source is higher.
            ip_type = 'ip-src'
            if isight_alert.networkType == 'C&C':
                ip_type = 'ip-dst'
        elif isight_alert.networkIdentifier == 'Compromised':
            # Might be source or destination, but likelihood of destination is higher.
            ip_type = 'ip-dst'
        elif isight_alert.networkIdentifier == 'Related':
            # Might be source or destination, but likelihood of source is higher.
            ip_type = 'ip-src'
        elif isight_alert.networkIdentifier == 'Victim':
            # Might be source or destination, but likelihood of destination is higher.
            ip_type = 'ip-dst'
        else:
            # Might be source or destination, but likelihood of source is higher.
            ip_type = 'ip-src'
        if isight_alert.port:
            # If a port is provided, it's likely a destination IP address.
            ip_type = 'ip-dst'
            type_combo = ip_type + '|port'
            ip_port = isight_alert.ip + '|' + isight_alert.port
            new_attr = event.add_attribute(category='Network activity', type=type_combo, value=ip_port,
                                           to_ids=network_ids, comment=ip_comment)
        else:
            new_attr = event.add_attribute(category='Network activity', type=ip_type, value=isight_alert.ip,
                                           to_ids=network_ids, comment=ip_comment)
        if isight_alert.networkType == 'C&C':
            # Add veris tag to attribute.
            new_attr.add_tag('veris:action:malware:variety="C2"')

    # If the report contains a domain registrant email address, then create a whois attribute.
    if isight_alert.registrantEmail:
        whois_object = MISPObject('whois')
        whois_object.comment = default_comment
        whois_object.add_attribute('registrant-email', value=isight_alert.registrantEmail, to_ids=network_ids)
        if isight_alert.registrantName:
            whois_object.add_attribute('registrant-name', value=isight_alert.registrantName, to_ids=False)
        if isight_alert.domain:
            whois_object.add_attribute('domain', value=isight_alert.domain, to_ids=network_ids)
        elif isight_alert.sourceDomain:
            whois_object.add_attribute('domain', value=isight_alert.sourceDomain, to_ids=network_ids)
        event.add_object(whois_object)

    # If the report contains a URL, create a url attribute.
    if isight_alert.url:
        event.add_attribute(category='Network activity', type='url', value=isight_alert.url, to_ids=network_ids,
                            comment=default_comment)
        if isight_alert.networkType == 'C&C':
            # Add veris tag to attribute.
            event.add_attribute_tag('veris:action:malware:variety="C2"', isight_alert.url)

    # If the report contains registry information, create a regkey attribute.
    # Ideally, the registry field would be split into hive, key and value.
    if isight_alert.registry:
        # If a file description is given, add it to the default comment.
        if isight_alert.description:
            add_comment = isight_alert.description
            if default_comment == '':
                reg_comment = add_comment
            else:
                reg_comment = default_comment + '; ' + add_comment
        else:
            reg_comment = default_comment
        event.add_attribute(category='Artifacts dropped', type='regkey', value=isight_alert.registry, to_ids=file_ids,
                            comment=reg_comment)

    # If the report contains a malware family, create a malware-type attribute.
    if isight_alert.malwareFamily:
        event.add_attribute(category='Antivirus detection', type='text', value=isight_alert.malwareFamily,
                            to_ids=False)

    # If the report contains an actor, create a threat-actor attribute.
    if isight_alert.actor:
        # Don't use the threat actor for detection.
        event.add_attribute(category='Attribution', type='threat-actor', value=isight_alert.actor, to_ids=False)

    # Finally, commit the event additions to the MISP instance.
    misp_instance.update_event(event)

    # Lastly, publish the event without sending an alert email.
    # This command expects the event ID instead of a MISPevent as argument.
    misp_instance.publish(event['id'], alert=False)


# Create a new MISP event.
def create_misp_event(misp_instance, isight_report_instance):
    # No MISP event for this iSight report ID exists yet.
    # Alas, create a new MISP event.

    # Convert the publication date of the iSight report into a datetime object.
    if isight_report_instance.publishDate:
        date = datetime.datetime.fromtimestamp(isight_report_instance.publishDate)
    else:
        # If iSight doesn't provide a date, use today's date.
        date = datetime.datetime.now(datetime.timezone.utc)

    # Create a MISP event from the FireEye iSight report with the following parameters.
    event = MISPEvent()
    event.distribution = 1  # This community only
    if isight_report_instance.riskRating == 'CRITICAL' or isight_report_instance.riskRating == 'Critical':
        event.threat_level_id = 1  # High
    elif isight_report_instance.riskRating == 'HIGH' or isight_report_instance.riskRating == 'High':
        event.threat_level_id = 1  # High
    elif isight_report_instance.riskRating == 'MEDIUM' or isight_report_instance.riskRating == 'Medium':
        event.threat_level_id = 2  # Medium
    elif isight_report_instance.riskRating == 'LOW' or isight_report_instance.riskRating == 'Low':
        event.threat_level_id = 3  # Low
    else:
        event.threat_level_id = 4  # Unknown
    event.analysis = 2  # Completed
    event.info = "iSIGHT: " + isight_report_instance.title
    event.date = date

    # Push the event to the MISP server.
    my_event = misp_instance.add_event(event, pythonify=True)
    PySight_settings.logger.debug('Created MISP event %s for iSight report %s', event, isight_report_instance.reportId)

    # Add default tags to the event.
    misp_instance.tag(my_event, 'basf:classification="internal"')
    #misp_instance.tag(my_event, 'basf:source="iSight"')
    misp_instance.tag(my_event, 'tlp:amber')

    # Use some iSight ThreatScapes for event tagging. Reports can have multiple ThreatScapes.
    if 'Cyber Espionage' in isight_report_instance.ThreatScape:
        # VERIS distinguishes between external, internal or partner actors. This difference is not yet implemented in
        # MISP. External would be most likely.
        #misp_instance.tag(my_event, 'veris:actor:external:motive="Espionage"')
        misp_instance.tag(my_event, 'veris:actor:motive="Espionage"')
    if 'Hacktivism' in isight_report_instance.ThreatScape:
        misp_instance.tag(my_event, 'veris:actor:external:variety="Activist"')
    if 'Critical Infrastructure' in isight_report_instance.ThreatScape:
        misp_instance.tag(my_event, 'basf:technology="OT"')
    if 'Cyber Physical' in isight_report_instance.ThreatScape:
        misp_instance.tag(my_event, 'basf:technology="OT"')
    if 'Cyber Crime' in isight_report_instance.ThreatScape:
        misp_instance.tag(my_event, 'veris:actor:external:variety="Organized crime"')

    # Add the iSight report ID and web link as attributes.
    if isight_report_instance.reportId:
        misp_instance.add_attribute(my_event, {'category': 'External analysis', 'type': 'text', 'to_ids': False,
                                               'value': isight_report_instance.reportId}, pythonify=True)
    if isight_report_instance.webLink:
        misp_instance.add_attribute(my_event, {'category': 'External analysis', 'type': 'link', 'to_ids': False,
                                               'value': isight_report_instance.webLink}, pythonify=True)

    # Put the ThreatScape into an Attribution attribute, but disable correlation.
    if isight_report_instance.ThreatScape:
        misp_instance.add_attribute(my_event, {'category': 'Attribution', 'type': 'text', 'to_ids': False,
                                               'value': isight_report_instance.ThreatScape,
                                               'disable_correlation': True}, pythonify=True)

    # Add specific attributes from this iSight report.
    update_misp_event(misp_instance, my_event, isight_report_instance)


# Retrieve the event ID of an event.
def check_misp_all_results(a_result):
    """
    :param a_result:
    :type a_result:
    :return: previous event from MISP
    :rtype:
    """
    # PySight_settings.logger.debug('Checking %s if it contains previous events', a_result)
    if 'message' in a_result:
        if a_result['message'] == 'No matches.':
            PySight_settings.logger.error('No existing MISP event found')
            # has really no event
            return False
    elif 'Event' in a_result[0]:
        previous_event = a_result[0]['Event']['id']
        PySight_settings.logger.debug('Found an existing MISP event with ID %s', previous_event)
        return previous_event
    else:
        for e in a_result['response']:
            previous_event = e['Event']['id']
            PySight_settings.logger.debug('Found an existing MISP event with ID %s', previous_event)
            return previous_event


# Check whether there already exists a MISP event for a specific FireEye iSight report.
def misp_check_for_previous_event(misp_instance, isight_alert):
    """
    Default: No event exists for this iSight report ID.

    :param misp_instance:
    :type misp_instance:
    :param isight_alert:
    :type isight_alert:
    :return:
        event id if an event is there
        false if no event exists yet
    :rtype:
    """
    event = False

    if misp_instance is None:
        PySight_settings.logger.error('No MISP instance provided')
        return False

    # Search based on report ID.
    if isight_alert.reportId:
        result = misp_instance.search(value=isight_alert.reportId, type_attribute='text', category='External analysis')
        # If something was found in the MISP instance, then retrieve the event
        if result:
            event = check_misp_all_results(result)

    # If no event found, search based on report URL.
    if isight_alert.webLink and not event:
        result = misp_instance.search(value=isight_alert.webLink, type_attribute='link', category='External analysis')
        # If something was found in the MISP instance, then retrieve the event
        if result:
            event = check_misp_all_results(result)

    if not result:
        PySight_settings.logger.debug('Found no existing event for iSight report ID %s', isight_alert.reportId)

    return event


# Generate a PyMISP instance.
def get_misp_instance():
    """
    :return: MISP Instance
    :rtype: PyMISP
    """
    # Proxy settings are taken from the config file and converted to a dict.
    if PySight_settings.USE_MISP_PROXY:
        misp_proxies = {
            'http': str(PySight_settings.proxy_address),
            'https': str(PySight_settings.proxy_address)
        }
    else:
        misp_proxies = {}

    try:
        # URL of the MISP instance, API key and SSL certificate validation are taken from the config file.
        return ExpandedPyMISP(PySight_settings.misp_url, PySight_settings.misp_key, PySight_settings.misp_verifycert,
                              proxies=misp_proxies)
        #return PyMISP(PySight_settings.misp_url, PySight_settings.misp_key, PySight_settings.misp_verifycert,
        #              proxies=misp_proxies)
    except Exception:
        PySight_settings.logger.error('Unexpected error in MISP init: %s', sys.exc_info())
        return False


# Process one FireEye iSight report and convert it into a MISP events.
def process_isight_indicator(a_json):
    """
    Create a pySightAlert instance of the json and make all the mappings

    :param a_json:
    :type a_json:
    """

    try:
        # Get a MISP instance per thread
        this_misp_instance = get_misp_instance()

        # Without a MISP instance this does not make sense
        if this_misp_instance is False:
            raise ValueError("No MISP instance found.")

        # Acquire a semaphore (decrease the counter in the semaphore).
        if PySight_settings.use_threading:
            thread_limiter.acquire()
        # PySight_settings.logger.debug("max number %s current number: ", thread_limiter._initial_value, )

        # Parse the FireEye iSight report
        isight_report_instance = pySightReport(a_json)

        # If in DEBUG mode, write the iSight reports to a file.
        if PySight_settings.debug_mode:
            # Create the "reports" subdirectory for storing iSight reports, if it doesn't exist already.
            if not os.path.exists("reports"):
                os.makedirs("reports")
            f = open("reports/" + isight_report_instance.reportId, 'a')
            # Write the iSight report into the "reports" subdirectory.
            f.write(json.dumps(a_json, sort_keys=True, indent=4, separators=(',', ': ')))
            f.close()

        # Check whether we already have an event for this reportID.
        PySight_settings.logger.debug('Checking for existing event with report ID %s', isight_report_instance.reportId)
        event_id = misp_check_for_previous_event(this_misp_instance, isight_report_instance)

        if not event_id:
            # Create a new MISP event
            PySight_settings.logger.debug('No event found for report ID %s -- will create a new one',
                                          isight_report_instance.reportId)
            create_misp_event(this_misp_instance, isight_report_instance)
        else:
            # Add the data to the found event
            event = this_misp_instance.get_event(event_id, pythonify=True)
            update_misp_event(this_misp_instance, event, isight_report_instance)

        # Reset the iSight report instance when done.
        isight_report_instance = None

        # Release the semaphore (increase the counter in the semaphore).
        if PySight_settings.use_threading:
            thread_limiter.release()

    except AttributeError as e_AttributeError:
        sys, traceback = error_handling(e_AttributeError, a_string="Attribute Error")
        return False
    except TypeError as e_TypeError:
        sys, traceback = error_handling(e_TypeError, a_string="Type Error:")
        return False
    except Exception as e_Exception:
        sys, traceback = error_handling(e_Exception, a_string="General Error:")
        return False


# Process all FireEye iSight reports and convert them to MISP events.
def misp_process_isight_indicators(a_result):
    """
    :param a_result:
    :type a_result:
    """

    # Process each indicator in the JSON message
    for indicator in a_result['message']:
        PySight_settings.logger.debug('Processing report %s', indicator['reportId'])

        if PySight_settings.use_threading:
            # Use threads to process the indicators
            # First, set the maximum number of threads
            thread_limiter = threading.BoundedSemaphore(value=PySight_settings.number_threads)
            # Define a thread
            t = threading.Thread(target=process_isight_indicator, args=(indicator,))
            # Start the thread
            t.start()
        else:
            # No threading
            process_isight_indicator(indicator)


# Make the FireEye iSight API request.
def isight_load_data(a_url, a_query, a_header):
    """
    :param a_url:
    :type a_url:
    :param a_query:
    :type a_query:
    :param a_header:
    :type a_header:
    :return:
    :rtype:
    """

    # This is the URL for the iSight API query
    url_to_load = a_url + a_query

    # Set the proxy if specified
    if PySight_settings.USE_ISIGHT_PROXY:
        isight_proxies = {
            'http': PySight_settings.proxy_address,
            'https': PySight_settings.proxy_address
        }
        PySight_settings.logger.debug('Connecting to FireEye iSight via proxy %s', PySight_settings.proxy_address)
    else:
        isight_proxies = {}
        PySight_settings.logger.debug('Connecting directly to FireEye iSight without a proxy',
                                      PySight_settings.proxy_address)

    PySight_settings.logger.debug('FireEye iSight request URL: %s', url_to_load)
    PySight_settings.logger.debug('FireEye iSight request header: %s', a_header)

    try:
        r = requests.get(url_to_load, headers=a_header, proxies=isight_proxies, verify=False)
    except urllib.error.HTTPError as e:
        PySight_settings.logger.error('Urllib HTTP error code: %s', e.code)
        PySight_settings.logger.error('Urllib HTTP error message: %s', e.read())
    except requests.exceptions.ChunkedEncodingError as e:
        PySight_settings.logger.error('Error when connecting to the FireEye iSight API: %s', e)
        return False

    if r.status_code == 204:
        PySight_settings.logger.warning('No result found for search')
        return False
    elif r.status_code == 404:
        PySight_settings.logger.error('%s: check the FireEye iSight API URL', r.reason)
        PySight_settings.logger.debug('%s', r.text)
        return False
    elif r.status_code != 200:
        PySight_settings.logger.error('Request not successful: %s', r.text)
        return False

    return_data_cleaned = r.text.replace('\n', '')

    json_return_data_cleaned = json.loads(return_data_cleaned)
    PySight_settings.logger.debug('Number of indicators returned: %s', len(json_return_data_cleaned['message']))

    if not json_return_data_cleaned['success']:
        PySight_settings.logger.error('Error with the FireEye iSight API connection %s',
                                      json_return_data_cleaned['message']['description'])
        PySight_settings.logger.debug(json_return_data_cleaned)
        return False
    else:
        # For debugging purposes, write the returned IOCs to a file
        if PySight_settings.debug_mode:
            timestring = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
            if not os.path.exists('debug'):
                os.makedirs('debug')
            f = open('debug/' + timestring, 'w')
            f.write(json.dumps(json_return_data_cleaned, sort_keys=True, indent=6, separators=(',', ': ')))
            f.close()

        return json_return_data_cleaned


# Define the header for the HTTP requests to the iSight API.
def set_header(a_prv_key, a_pub_key, a_query):
    """
    :param a_prv_key:
    :type a_prv_key:
    :param a_pub_key:
    :type a_pub_key:
    :param a_query:
    :type a_query:
    :return: Header for iSight search
    :rtype:
    """

    # Prepare the data to calculate the X-Auth-Hash.
    accept_version = '2.5'
    output_format = 'application/json'
    time_stamp = email.utils.formatdate(localtime=True)
    string_to_hash = a_query + accept_version + output_format + time_stamp

    # Convert the authentication information from UTF-8 encoding to a bytes object
    message = bytes(string_to_hash, 'utf-8')
    secret = bytes(a_prv_key, 'utf-8')

    # Hash the authentication information
    hashed = hmac.new(secret, message, hashlib.sha256)

    header = {
        'X-Auth': a_pub_key,
        'X-Auth-Hash': hashed.hexdigest(),
        'Accept': output_format,
        'Accept-Version': accept_version,
        'Date': time_stamp
    }
    return header


# Prepare the request to the FireEye iSight API.
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
    header = set_header(a_prv_key, a_pub_key, a_query)
    result = isight_load_data(a_url, a_query, header)

    if not result:
        PySight_settings.logger.error('Something went wrong when retrieving indicators from the FireEye iSight API')
        return False
    else:
        return result


# Search for FireEye iSight reports published since the specified last hours.
def isight_search_indicators(base_url, public_key, private_key, hours):
    # Convert hours to seconds and subtract them from the current time
    since = int(time.time()) - hours * 60 * 60

    # Limit the returned data to that published since this Epoch datetime and the present time.
    # Therefore, add the 'since' parameter as a query string.
    params = {
        'since': since
    }
    search_query = '/view/indicators?' + urllib.parse.urlencode(params)

    # Retrieve indicators and warning data since the specified date and time.
    return isight_prepare_data_request(base_url, search_query, public_key, private_key)


# This function is called from test_pysight.py but otherwise not used.
def data_search_report(url, public_key, private_key, a_reportid):
    print("text_search_wildcard Response:")
    # wild card text search
    # FIXME: not used
    # params = {
    #    'reportID': a_reportid
    # }
    text_search_query = '/report/' + a_reportid
    isight_prepare_data_request(url, text_search_query, public_key, private_key)


# This function is not used.
def data_text_search_title(url, public_key, private_key):
    print("text_search_title Response:")
    # title phrase search
    params = {
        'text': 'title:"Software Stack 3.1.2"'
    }
    text_search_query = '/search/text?' + urllib.urlencode(params)
    isight_prepare_data_request(url, text_search_query, public_key, private_key)


# This function is not used.
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


# This function is not used.
def data_text_search_sensitive_reports(url, public_key, private_key):
    print("text_search_sensitive_reports Response:")
    params = {
        'text': 'title:"Latin American"',
        'customerIntelOnly': True
    }
    text_search_query = '/search/text?' + urllib.urlencode(params)
    isight_prepare_data_request(url, text_search_query, public_key, private_key)


# This function is not used.
def data_advanced_search_filter_indicators(url, public_key, private_key):
    print("advanced_search_filter_indicators Response:")
    # Indicator field md5
    advanced_search_query = '/search/advanced?query=md5=~8512835a95d0fabfb&fileIdentifier=[Victim;Attacker]'
    isight_prepare_data_request(url, advanced_search_query, public_key, private_key)


# This function is not used.
def data_basic_search_ip(url, public_key, private_key, ip):
    PySight_settings.logger.debug("basic_search Response")
    # Query for search
    basic_search_query = '/search/basic?ip=' + ip
    isight_prepare_data_request(url, basic_search_query, public_key, private_key)


# This function is not used.
def data_ioc(url, public_key, private_key):
    # print ("iocs Response:")
    # 30 days back start date
    start_date = int(time.time()) - 2592000
    end_date = int(time.time())
    ioc_query = '/view/iocs?' + 'start_date=' + str(start_date) + '&end_date=' + str(end_date)
    return isight_prepare_data_request(url, ioc_query, public_key, private_key)


# This function is not used.
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


# This function is not used.
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


if __name__ == '__main__':
    # If loglevel equals DEBUG, log the time the script ran.
    PySight_settings.logger.info('PySight2MISP started at %s', datetime.datetime.now(datetime.timezone.utc))
    if PySight_settings.debug_mode:
        # This is to log the time used to run the script
        from timeit import default_timer as timer
        start = timer()

    # Retrieve FireEye iSight indicators of the last x hours.
    result = isight_search_indicators(PySight_settings.isight_url, PySight_settings.isight_pub_key,
                                      PySight_settings.isight_priv_key, PySight_settings.isight_last_hours)
    if result is False:
        PySight_settings.logger.warning('No indicators available from FireEye iSight')
    else:
        misp_process_isight_indicators(result)

    PySight_settings.logger.info('PySight2MISP finished at %s', datetime.datetime.now(datetime.timezone.utc))
    # If loglevel equals DEBUG, log the time the script ran.
    if PySight_settings.debug_mode:
        end = timer()
        PySight_settings.logger.debug('Time taken %s', end - start)

    # data_ioc(url, public_key, private_key)
    # data_text_search_simple(isight_url, public_key, private_key)
    # data_text_search_filter(isight_url, public_key, private_key)
    # data_text_search_title(url, public_key, private_key)
    # data_text_search_wildcard(url, public_key, private_key)
    # data_text_search_sensitive_reports(isight_url, public_key, private_key)
    # data_advanced_search_filter_indicators(url, public_key, private_key)
