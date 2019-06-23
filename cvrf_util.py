#!/usr/bin/env python
"""
Description:
Utility to parse and validate a CSAF Common Vulnerability Reporting Framework (CVRF)
file and display user-specified fields.

For additional information about CSAF or CVRF visit:
https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=csaf

Requirements:
* lxml (version 3.7.3)

This tool is based on the original cvrfparse utility created by Mike Schiffman of
Farsight Security under the MIT License. https://github.com/mschiffm/cvrfparse
"""

from __future__ import print_function

import os
import sys
import logging
from cvrf_parser.cvrf_util import main

__revision__ = "1.2.0"


if __name__ == "__main__":
    progname = os.path.basename(sys.argv[0])

    try:
        main(progname)
    except Exception:
        (exc_type, exc_value, exc_tb) = sys.exc_info()
        sys.excepthook(exc_type, exc_value, exc_tb)  # if debugging
        sys.exit("%s: %s: %s" % (progname, exc_type.__name__, exc_value))

    logging.info('bye bye')
    sys.exit(0)
