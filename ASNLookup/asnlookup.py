#!/usr/bin/env python3
# encoding: utf-8

"""
A Cortex Analyzer that retrieves ASN, prefix, and network names for IP addresses using Shadowserver.org's
IP-BGP service https://shadowserver.org/wiki/pmwiki.php/Services/IP-BGP
"""

from RashlyOutlaid.libwhois import ASNWhois
from cortexutils.analyzer import Analyzer


class ASNLookup(Analyzer):
    def __init__(self):
        # Bootstrap our ancestor
        Analyzer.__init__(self)
        # We don't want to extract observables for Hive from this
        self.auto_extract = False

    def summary(self, raw):
        """
        'raw' is the json that's returned in the report
        """
        taxonomies = [ ]
        level = "info"
        namespace = "ASNLookup"
        asname = raw[ 'IPBGP' ][ 'asn' ]
        isp = raw[ 'IPBGP' ][ 'isp' ]
        predicate = "AS"
        value = "{0} - {1}".format(asname,isp)
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def search_bgpip(self, ip):

        asnwhois = ASNWhois()
        asnwhois.query = [ ip ]
        ret = asnwhois.result[asnwhois.query[0]]._asdict()

        # Remove keys we don't need
        for key in ['peers']:
            ret.pop(key, None)
        return ret

    def run(self):
        """
        Run the analysis here
        """
        Analyzer.run(self)

        if self.data_type == 'ip':
            try:

                ## Just get some json, using the user input as the seach query
                bgpip = self.search_bgpip(self.getData())

                ## This gets put back to the summary report object
                self.report({
                    'IPBGP': bgpip
                })

            except ValueError as e:
                self.unexpectedError(e)
        else:
            self.notSupported()


if __name__ == '__main__':
    ASNLookup().run()
