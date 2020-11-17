#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# check_sslscan - check server against Qualys sslscan
# author, (c): Philippe Kueck <projects at unixadm dot org>

from optparse import OptionParser, OptionGroup

import ssl
from urllib.parse import urlencode, quote
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

import json
import signal
import time

scores = {
    'A+': 7, 'A':  6, 'A-': 5, 'B':  4, 'C':  3,
    'D':  2, 'E':  1, 'F':  0, 'T':  0, 'M':  0
}

class SSLScan:

    def __init__(self, host, publish=False, maxAge=0, nocache=False, trust=True):
        self.uri = "https://api.ssllabs.com/api/v2/analyze?host=%s&" % host
        self.args = ['publish=%s' % ("off","on")[publish]]
        self.trust = trust
        if nocache: self.args += ['startNew=on']
        else:
            self.args += ['fromCache=on']
            if maxAge > 0: self.args += ['maxAge=%d' % maxAge]

        self.headers = {
            'Accept': "application/json",
            'User-Agent': "nagios/check_sslscan"
        }

    def get_results(self):
        return self.poll(True)

    def poll(self, start=False):

        if start: uri = self.uri + ("&".join(self.args))
        else: uri = self.uri + "all=done"

        req = Request(uri, headers=self.headers)
        try:
            with urlopen(req, None, 60) as fh:
                data = json.loads(fh.read())
        except json.decoder.JSONDecodeError:
            raise Exception("invalid json received")
        except Exception as e:
            if e.status == 529:
                time.sleep(10)
                return self.poll(start=True)
            raise Exception("ssllabs returned status code %d" % e.status)

        print(data)
        if data['status'] == "ERROR":
            raise Exception(data['statusMessage'])

        if data['status'] == "READY":
            if self.trust:
                return list(set([e['grade'] for e in data['endpoints']]))
            return list(set([e['gradeTrustIgnored'] for e in data['endpoints']]))

        if data['status'] in ['DNS', 'IN_PROGRESS']:
            time.sleep(10)
            return self.poll()

        raise Exception("this should never happen, status %s" % data['status'])


def nagexit(exitc, status):
    print("{0}: {1}".format(
        {0:'OK',1:'WARNING',2:'CRITICAL',3:'UNKNOWN'}[exitc],
        status
    ))
    exit(exitc)

def timeouthandler(signum, frame):
    nagexit(3, "timeout")

def main():
    sslscan = SSLScan(options.host,
        publish=options.publish,
        maxAge=options.maxage,
        nocache=options.nocache,
        trust=not options.ignoretrust
    )

    try: res = sslscan.get_results()
    except Exception as e: nagexit(2, str(e))

    rc = 0
    for r in res:
        if scores[r] <= scores[options.crit] and rc < 2: rc = 2
        if scores[r] <= scores[options.warn] and rc < 1: rc = 1
    nagexit(rc, "score(s) %s" % ",".join(res))

if __name__ == "__main__":
    signal.signal(signal.SIGALRM, timeouthandler)
    signal.alarm(900)

    desc = "%prog check server's ssl score"
    parser = OptionParser(description=desc, version="%prog version 1.0")

    gen_opts = OptionGroup(parser, "Generic options")
    thres_opts = OptionGroup(parser, "Threshold options")
    parser.add_option_group(gen_opts)
    parser.add_option_group(thres_opts)

    thres_opts.add_option("-w", "--warn", dest="warn",
        type="string", action="store", default="B",
        help="warn at or below this grade"
    )

    thres_opts.add_option("-c", "--crit", dest="crit",
        type="string", action="store", default="C",
        help="crit at or below this grade"
    )

    gen_opts.add_option("-H", "--host", dest="host",
        type="string", action="store",
        help="hostname to check"
    )

    gen_opts.add_option("-i", "--ip", dest="ip",
        type="string", action="store",
        help="ip address to use if the host has more than one endpoint"
    )

    gen_opts.add_option("-t", "--ignore-trust", dest="ignoretrust",
        action="store_true", default=False,
        help="retrieve the trust-adjusted score(s), ignoring certificate trust issues"
    )

    gen_opts.add_option("-a", "--maxage", dest="maxage",
        type="int", metavar="HOURS", action="store", default=0,
        help="set max cache age in hours (unless --nocache is set)"
    )

    gen_opts.add_option("-x", "--nocache", dest="nocache",
        action="store_true", default=False,
        help="do not accept cached results"
    )

    gen_opts.add_option("-p", "--publish", dest="publish",
        action="store_true", default=False,
        help="publish results at Qualys SSL Labs"
    )

    (options, args) = parser.parse_args()

    if options.warn not in scores or options.crit not in scores:
        nagexit(3, "invalid score specified")

    main()

    signal.alarm(0)
