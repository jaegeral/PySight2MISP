import unittest

import PySight_settings
from PySight import misp_process_isight_alert,data_search_report,test_isight_connection, misp_delete_events, \
    isight_process_alert_content_element, get_misp_instance,data_search_indicators_since


class OnlineTestCases(unittest.TestCase):
    def test_is_isight_working(self):
        """Is test api there aka connection test"""
        self.assertTrue(test_isight_connection())


    def test_get_isight_reports_last(self):
        import time
        since = int(time.time()) - 720 * 60 * 60
        print (since)
        return_value = data_search_indicators_since(private_key=PySight_settings.isight_priv_key,public_key=PySight_settings.isight_pub_key,since=since,url=PySight_settings.isight_url)
        import json
        print(json.dumps(return_value, sort_keys=True, indent=4))
        self.assertIsNotNone(return_value)


    def test_get_24hours_isight_report_and_push_misp(self):
        import time
        since = int(time.time()) - 720 * 60 * 60
        print(since)
        return_value = data_search_indicators_since(private_key=PySight_settings.isight_priv_key,
                                                    public_key=PySight_settings.isight_pub_key, since=since,
                                                    url=PySight_settings.isight_url)
        import json
        print(json.dumps(return_value, sort_keys=True, indent=4))

        misp_process_isight_alert(return_value)

        self.assertIsNotNone(return_value)



    def test_is_misp_working(self):
        localmisp = get_misp_instance()
        self.assertIsNotNone(localmisp)

    def test_get_specific_report2(self):
        localmisp = get_misp_instance()
        event = localmisp.get_event('2355')
        for temp in event['Event']['Attribute']:
            if temp['id'] == '34539':
                attribute = temp
                break
        import json
        print(json.dumps(event, sort_keys=True, indent=4))
        print (event['Event']['Attribute'])
        localmisp.add_tag(attribute, 'PAP:GREEN', attribute=True)
        localmisp.add_tag(event, 'PAP:GREEN', attribute=False)


    def test_get_specific_report(self):
        localmisp = get_misp_instance()
        result = data_search_report(url=PySight_settings.isight_url,private_key=PySight_settings.isight_priv_key,public_key=PySight_settings.isight_pub_key,a_reportid="16-00017916")
        misp_process_isight_alert(result)


        #result = data_search_indicators_last24_h(PySight_settings.isight_url, PySight_settings.isight_pub_key,
        #                                         PySight_settings.isight_priv_key)


class OfflineTestCases(unittest.TestCase):
    def test_parse_example_indicator(self):
        import json
        json_data = json.load(open("test_data/example_indicator.json"))
        PySight_settings.logger.debug(json.dumps(json_data['message'], sort_keys=True, indent=4))
        #for i in json_data['message']:
        returnvalue = isight_process_alert_content_element(json_data['message'])
        #logger.debug("hols %s",json.dumps(i, sort_keys=True, indent=4))

        #returnvalue = pySightReport(json_data['message'])
        #logger.debug("Return valuer: %s",returnvalue)

        #self.assertIsNot(returnvalue,None,"Message received and not none")
        self.assertIsNot(returnvalue,False,"Message is false, something went wrong")

    def test_parse_example_report(self):
        import json
        json_data = json.load(open("test_data/example_report.json"))
        PySight_settings.logger.debug(json.dumps(json_data['message'], sort_keys=True, indent=4))
        # for i in json_data['message']:
        returnvalue = isight_process_alert_content_element(json_data['message'])
        # logger.debug("hols %s",json.dumps(i, sort_keys=True, indent=4))

        # returnvalue = pySightReport(json_data['message'])
        # logger.debug("Return valuer: %s",returnvalue)

        # self.assertIsNot(returnvalue,None,"Message received and not none")
        self.assertIsNot(returnvalue, False, "Message is false, something went wrong")

    def test_parse_example_report_from_struart(self):
        import json
        json_data = json.load(open("test_data/real/16-00014704.json"))
        PySight_settings.logger.debug(json.dumps(json_data['report'], sort_keys=True, indent=4))
        # for i in json_data['message']:
        returnvalue = isight_process_alert_content_element(json_data['report'])
        # logger.debug("hols %s",json.dumps(i, sort_keys=True, indent=4))

        # returnvalue = pySightReport(json_data['message'])
        # logger.debug("Return valuer: %s",returnvalue)

        # self.assertIsNot(returnvalue,None,"Message received and not none")
        self.assertIsNot(returnvalue, False, "Message is false, something went wrong")


    def test_parse_example_indicator_c2(self):
        import json
        json_data = json.load(open("test_data/example_indicator_c2.json"))
        #logger.debug(json.dumps(json_data['message'], sort_keys=True, indent=4))

        # for i in json_data['message']:
        returnvalue = isight_process_alert_content_element(json_data['message'])
        # logger.debug("hols %s",json.dumps(i, sort_keys=True, indent=4))

        # returnvalue = pySightReport(json_data['message'])
        # logger.debug("Return valuer: %s",returnvalue)

        # self.assertIsNot(returnvalue,None,"Message received and not none")
        self.assertIsNot(returnvalue, False, "Message is false, something went wrong")

    # Not a good test case
    #def test_find_previous_events(self):
    #    self.assertIsNot(check_misp_all_result("16-00011458"),False)



    # def test_is_error_catched_with_wrong_credentials(self):
    #    print("asd")

    # def test_data_text_search_filter(self):
    #    self.assertIsNot(data_text_search_filter(isight_url, isight_pub_key, isight_priv_key), False)

    def test_delete_misp_events(self):
        localmisp = get_misp_instance()
        self.assertFalse(misp_delete_events(1519,1519,localmisp))
        self.assertTrue(misp_delete_events(1519,1519,localmisp))


    #def test_search_ip(self):
    #    data_basic_search_ip(isight_url, isight_pub_key, isight_priv_key, '8.8.8.8')
    #    self.assertTrue(data_basic_search_ip(isight_url, isight_pub_key, isight_priv_key,'8.8.8.8'))


if __name__ == '__main__':
    unittest.main()