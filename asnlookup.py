#!/usr/bin/env python
# encoding: utf-8
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

        return dict(network=raw['BGP-IP']['isp'])

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
                    'BGP-IP': bgpip
                })

            except ValueError as e:
                self.unexpectedError(e)
        else:
            self.notSupported()


if __name__ == '__main__':
    ASNLookup().run()
