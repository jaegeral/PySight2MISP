"""
"network": [
                    {
                        "domain": "in-travelusa.com",
                        "actorId": "73c877bb-54fb-4f0a-90f8-c250bc303bcc",
                        "protocol": "HTTP",
                        "actor": "FIN7",
                        "networkType": "C&C",
                        "identifier": "Attacker"
                    },
"""

class iSightNetwork:
    def __init__(self,a_network_json):
        self.domain = None
        self.actorId = None
        self.protocol = None
        self.actor = None
        self.networkType = None
        self.identifier = None
        self._parse_json(a_network_json)

    def _parse_json(self, a_network_json):
        if not a_network_json:
            raise ValueError('No Json given')

        if 'domain' in a_network_json:
            self.domain = str(a_network_json['domain'])

        if 'actorId' in a_network_json:
            self.actorId = str(a_network_json['actorId'])

        if 'protocol' in a_network_json:
            self.protocol = str(a_network_json['protocol'])

        if 'actor' in a_network_json:
            self.actor = str(a_network_json['actor'])

        if 'identifier' in a_network_json:
            self.identifier = str(a_network_json['identifier'])

        if 'networkType' in a_network_json:
            self.networkType = str(a_network_json['networkType'])


        # Print out the Json given to the method
        # logger.debug(json.dumps(p_alert_json, sort_keys=False, indent=4, separators=(',', ': ')))