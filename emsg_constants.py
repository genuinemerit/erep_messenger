# coding: utf-8
#!/usr/bin/python3
"""
:module:  emsg_constants
:class:   EmsgConstants

Global constants.

:author:    PQ <pq_rfw @ pm.me>
"""

class EmsgConstants(object):
    """
    Standard constants, reference codes and structures.

    Provides constants for:

      - Severity levels
      - Hash lengths and codes
      - Default time zone
      - Command-line display-related values for tabs and newlines

    """
    def __init__(self):
        self.LOGLEVEL = {'CRITICAL': 50,
                         'FATAL': 50,
                         'ERROR': 40,
                         'WARNING': 30,
                         'NOTICE': 20,
                         'INFO': 20,
                         'DEBUG': 10,
                         'NOTSET': 0 }
        self.SHA512 = 128
        self.SHA256 = 64
        self.SHA224 = 56
        self.SHA1 = 40
        self.HASH_ALGO = {
            40: 'SHA1',
            56: 'SHA224',
            64: 'SHA256',
           128:'SHA512' }
        self.DFLT_TZ = 'US/Eastern'
        self.NT0 = '\n'
        self.NT1 = '\n\t'
        self.NT2 = '\n\t\t'
        self.T1 = '\t'
        self.T2 = '\t\t'
        self.NOT_DELETED = '9999-99-99 99:99:99.99999 +00:00'
