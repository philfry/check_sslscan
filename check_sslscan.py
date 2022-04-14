#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# check_sslscan - check server against Qualys sslscan
# author, (c): Philippe Kueck <projects at unixadm dot org>

from argparse import ArgumentParser

import ssl
from urllib.parse import urlencode, quote
from urllib.request import Request, urlopen, ProxyHandler, build_opener, install_opener
from urllib.error import URLError, HTTPError

import sys
import json
import signal
import time

__version__ = "1.2"

scores = {
    'A+': 7, 'A':  6, 'A-': 5, 'B':  4, 'C':  3,
    'D':  2, 'E':  1, 'F':  0, 'T':  0, 'M':  0
}

class SSLScan:

    def __init__(self, host, publish=False, maxAge=0, nocache=False, trust=True, proxy=None, debug=False):
        self.uri = "https://api.ssllabs.com/api/v2/analyze?host=%s&" % host
        self.args = ['publish=%s' % ("off","on")[publish]]
        self.trust = trust
        self.debug = debug
        if proxy is not None:
            proxy_opener = build_opener(ProxyHandler({"https":proxy}))
            install_opener(proxy_opener)

        if nocache: self.args += ['startNew=on']
        else:
            self.args += ['fromCache=on']
            if maxAge > 0: self.args += ['maxAge=%d' % maxAge]

        self.headers = {
            'Accept': "application/json",
            'User-Agent': f"nagios/check_sslscan {__version__}"
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
                if self.debug: print(data, file=sys.stderr)
        except json.decoder.JSONDecodeError:
            raise Exception("invalid json received")
        except URLError as e:
            raise Exception(e.reason)
        except Exception as e:
            if e.status == 529:
                time.sleep(10)
                return self.poll(start=True)
            raise Exception("ssllabs returned status code %d" % e.status)

        if "errors" in data:
            raise Exception(
                "\n".join([i['message'] for i in data['errors']])
            )
        if data['status'] == "ERROR":
            raise Exception(data['statusMessage'])

        if data['status'] == "READY":
            for e in data['endpoints']:
                if e['progress'] < 0:
                    raise Exception(f"{e['ipAddress']}: {e['statusMessage']}")
            grade_k = ("gradeTrustIgnored", "grade")[self.trust]
            return list(set([e[grade_k] for e in data['endpoints'] if grade_k in e]))

        if data['status'] in ['DNS', 'IN_PROGRESS']:
            time.sleep(max([5]+[e['eta'] for e in data['endpoints']]))
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
        trust=not options.ignoretrust,
        proxy=options.proxy,
        debug=options.debug
    )

    try: res = sslscan.get_results()
    except Exception as e: nagexit(3, str(e))

    rc = 0
    for r in res:
        if scores[r] <= scores[options.crit] and rc < 2: rc = 2
        if scores[r] <= scores[options.warn] and rc < 1: rc = 1
    nagexit(rc, "score(s) %s" % ",".join(res))

if __name__ == "__main__":
    signal.signal(signal.SIGALRM, timeouthandler)
    signal.alarm(900)

    parser = ArgumentParser(
        description="%(prog)s: check server's ssl score"
    )

    gen_opts = parser.add_argument_group("Generic options")
    thres_opts = parser.add_argument_group("Threshold options")

    parser.add_argument('-V', '--version', action='version', version='%(prog)s ' + __version__)

    thres_opts.add_argument("-w", "--warn", dest="warn",
        type=str, metavar="RATING", action="store", default="B",
        choices=list(scores),
        help="warn at or below this grade"
    )

    thres_opts.add_argument("-c", "--crit", dest="crit",
        type=str, metavar="RATING", action="store", default="C",
        choices=list(scores),
        help="crit at or below this grade"
    )

    gen_opts.add_argument("-H", "--host", dest="host",
        type=str, action="store", required=True,
        help="hostname to check"
    )

    gen_opts.add_argument("-i", "--ip", dest="ip",
        type=str, action="store",
        help="ip address to use if the host has more than one endpoint"
    )

    gen_opts.add_argument("-t", "--ignore-trust", dest="ignoretrust",
        action="store_true", default=False,
        help="retrieve the trust-adjusted score(s), ignoring certificate trust issues"
    )

    gen_opts.add_argument("-a", "--maxage", dest="maxage",
        type=int, metavar="HOURS", action="store", default=0,
        help="set max cache age in hours (unless --nocache is set)"
    )

    gen_opts.add_argument("-x", "--nocache", dest="nocache",
        action="store_true", default=False,
        help="do not accept cached results"
    )

    gen_opts.add_argument("-p", "--publish", dest="publish",
        action="store_true", default=False,
        help="publish results at Qualys SSL Labs"
    )

    gen_opts.add_argument("--proxy", dest="proxy",
        type=str, metavar="ADDRESS", action="store",
        help="use proxy to connect to the ssllabs api"
    )

    gen_opts.add_argument("-d", "--debug", dest="debug",
        action="store_true", default=False,
        help="debug mode"
    )

    options = parser.parse_args()

    main()

    signal.alarm(0)
