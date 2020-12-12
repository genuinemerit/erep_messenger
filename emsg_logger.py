# -*- coding: utf-8 -*-
#!/usr/bin/python3
"""
:module:  emsg_logger
:class:   EmsgLogger

Generic logging class

:author:    PQ <pq_rfw @ pm.me>
"""
import logging
from os import chdir, getcwd, listdir, mknod, path, remove
from pprint import pprint as pp
from tornado.options import define, options
from emsg_constants import EmsgConstants
from emsg_functions import EmsgFunctions
EC = EmsgConstants()
EF = EmsgFunctions()

class EmsgLogger(object):
    """
    @class: EmsgLogger

    Generic logging functions for use with logging module.
    """
    def __init__(self, p_log_file, p_log_level=None):
        """ Initialize the EmsgLogger class """
        self.LOGLEVEL = self.set_log_level(p_log_level)
        self.LOGFILE = p_log_file
        dttm = EF.get_dttm(p_tzone='America/Los_Angeles')
        write_log_title = True if not path.exists(self.LOGFILE) else False
        f = open(self.LOGFILE, 'a+')
        if write_log_title:
            f.write("eRepublik Messenger Log File\n\n")
        f.write("\n===== {} {} =====\n\n".format("Session started at eRep Date/Time:", dttm.curr_lcl))
        f.close()

    def set_log_level(self, p_log_level=None):
        """
        Return an integer for use by Python logging module.

        :Args: {string} that is an index to LOGLEVEL or None or other

        :Return: {integer} valid value from LOGLEVEL
        """
        if p_log_level is None:
            return EC.LOGLEVEL['INFO']
        else:
            if p_log_level in EC.LOGLEVEL:
                return EC.LOGLEVEL[p_log_level]
            else:
                return EC.LOGLEVEL['NOTSET']

    def get_log_level(self, p_log_level_int):
        """
        Return string associated with specified LOGLEVEL integer value

        :Args: {int} Numeric value of a LOGLEVEL
        """
        for key, val in EC.LOGLEVEL.items():
            if val == p_log_level_int:
                return key
        return 'UNKNOWN'

    def set_logs(self):
        """
        Set log level, log formatter and log outputs
        """
        self.log = logging.getLogger()
        self.log.setLevel(self.LOGLEVEL)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        logF = logging.FileHandler(self.LOGFILE)
        logF.setLevel(self.LOGLEVEL)
        logF.setFormatter(formatter)
        self.log.addHandler(logF)

    def write_log(self, msg_level, msg_text):
        """
        Write message if appropriate level

        :Args:
          - {string} Name of (i.e., key to) a LOGLEVEL
          - {string} Content of the message to log
        """
        if msg_level not in EC.LOGLEVEL:
            ll_text = self.get_log_level(msg_level)
        else:
            ll_text = msg_level
        if ll_text in ('CRITICAL', 'FATAL'):
            logging.fatal(msg_text)
        elif ll_text == 'ERROR':
            logging.error(msg_text)
        elif ll_text == 'WARNING':
            logging.warning(msg_text)
        elif ll_text in ('NOTICE', 'INFO'):
            logging.info(msg_text)
        elif ll_text == 'DEBUG':
            logging.debug(msg_text)

    def close_logs(self):
        """
        Close log handlers
        """
        for handler in self.log.handlers:
            handler.close()
            self.log.removeFilter(handler)
