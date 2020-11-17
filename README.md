Usage: check_sslscan.py [options]

check_sslscan.py check server's ssl score

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit

  Generic options:
    -H HOST, --host=HOST
                        hostname to check
    -i IP, --ip=IP      ip address to use if the host has more than one
                        endpoint
    -t, --ignore-trust  retrieve the trust-adjusted score(s), ignoring
                        certificate trust issues
    -a HOURS, --maxage=HOURS
                        set max cache age in hours (unless --nocache is set)
    -x, --nocache       do not accept cached results
    -p, --publish       publish results at Qualys SSL Labs

  Threshold options:
    -w WARN, --warn=WARN
                        warn at or below this grade
    -c CRIT, --crit=CRIT
                        crit at or below this grade
