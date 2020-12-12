# coding: utf-8
#!/usr/bin/python3
"""
:module:    emsg_functions
:class:     EmsgFunctions

Global constants and generic helper functions.

:author:    PQ <pq_rfw @ pm.me>
"""
import arrow
import hashlib
import json
import subprocess as shl
import time
import traceback
from collections import namedtuple
from os import path
from pprint import pprint as pp
from emsg_constants import EmsgConstants
EC = EmsgConstants()

class EmsgFunctions(object):
    """
    Generic static methods.
    Functions for common tasks.
    """

    @classmethod
    def get_dttm(cls, p_tzone=None):
        """
        Return a named tuple with date and time values.

        :Args: {string} optional; valid Unix-style time zone or None
          Examples:  America/New_York  Asia/Shanghai  Europe/Dublin  Etc/UTC  Etc/Zulu  US/Eastern   UTC

        :Return: {namedtuple}

            - .tz {string} Local timezone (YYYY-MM-DD HH:mm:ss.SSSSS ZZ)
            - .curr_lcl {string} Local timezone date time
            - .next_lcl {string} Local date time plus 1 day
            - .curr_utc {string} UTC date time (YYYY-MM-DD HH:mm:ss.SSSSS ZZ)
            - .next_utc {string} UTC date time plus 1 day
            - .curr_ts  {string} UTC time stamp (YYYYMMDDHHmmssSSSSS)
        """
        tzone = str()
        curr_lcl = str()
        next_lcl = str()
        curr_utc = str()
        next_utc = str()
        curr_ts = str()
        tzone = EC.DFLT_TZ if p_tzone is None else p_tzone
        try:
            l_dttm = arrow.now(tzone)
        except arrow.parser.ParserError as _:
            tzone = EC.DFLT_TZ
            l_dttm = arrow.now(tzone)
        curr_lcl = str(l_dttm.format('YYYY-MM-DD HH:mm:ss.SSSSS ZZ'))
        curr_lcl_short = str(l_dttm.format('YYYY-MM-DD HH:mm:ss'))
        next_lcl = str(l_dttm.shift(days=+1).format('YYYY-MM-DD HH:mm:ss.SSSSS ZZ'))
        u_dttm = arrow.utcnow()
        curr_utc = str(u_dttm.format('YYYY-MM-DD HH:mm:ss.SSSSS ZZ'))
        next_utc = str(u_dttm.shift(days=+1).format('YYYY-MM-DD HH:mm:ss.SSSSS ZZ'))
        curr_ts = curr_utc.strip()
        curr_ts = curr_ts.replace(' ', '').replace(':', '').replace('-', '')
        curr_ts = curr_ts.replace('+', '').replace('.', '')
        curr_ts = curr_ts[0:-4]
        dttm = namedtuple('dttm', 'tz curr_lcl curr_lcl_short next_lcl curr_utc next_utc curr_ts')
        return dttm(tzone, curr_lcl, curr_lcl_short, next_lcl, curr_utc, next_utc, curr_ts)

    @classmethod
    def hash_me(cls, p_str, p_len=64):
        """
        Create a hash of the input string, returning a UTF-8 hex-string.

            - 128-byte hash uses SHA512
            - 64-byte hash uses SHA256
            - 56-byte hash uses SHA224
            - 40-byte hash uses SHA1

        :Args:

            - {string} to be hashed
            - {integer} Optional; length of hash to return

        :Return: {string} UTF-8-encoded hash of input argument
        """
        v_hash = str()
        v_len = EC.SHA256 if p_len is None else EC.SHA256 if p_len not in EC.HASH_ALGO else p_len
        if v_len == EC.SHA512:
            v_hash = hashlib.sha512()
        elif v_len == EC.SHA256:
            v_hash = hashlib.sha256()
        elif v_len == EC.SHA224:
            v_hash = hashlib.sha224()
        elif v_len == EC.SHA1:
            v_hash = hashlib.sha1()

        v_hash.update(p_str.encode("utf-8"))
        return v_hash.hexdigest()

    @classmethod
    def list_ports(cls, p_ports_config, p_class_name):
        """
        Return a list with all valid ports for selected class, based on parsing a configuration setting

        :Attr:
            - {string} in the format "ClassName:PortNum:PortNum ..(bis).." for a range
              or "ClassName:PortNum .." if only one port, where "PortNum" is an integer.
            - {string} class name to return ports for

        :Return: {list} of integers
        """
        ports = list()
        app_ports = list()
        if ' ' in p_ports_config:
            app_ports = p_ports_config.split(' ')
        else:
            app_ports.append(p_ports_config)
        for apport in app_ports:
            a_port = apport.split(':')
            if a_port[0] == p_class_name:
                if len(apport) == 2:
                    ports.append(a_port[1])
                else:
                    port_cnt = (int(a_port[2]) - int(a_port[1])) + 1
                    for pc in range(0, port_cnt):
                        ports.append(int(a_port[1]) + pc)
        return ports

    @classmethod
    def pluralize(cls, singular):
        """
        Return the plural form of the singular English word.

        :Args:  {string} singular English noun

        :Return:  {string} plural version of the noun
        """
        plural = singular
        if not singular or singular.strip() == ''\
                        or singular[-2:] in ('es', 'ds', 'ts', 'ms', 'hs', 'ps')\
                        or singular == 'stuff':
            pass
        elif singular[-1:] in ('s', 'x') or singular[-2:] in ('ch'):
            plural = singular + "es"
        elif singular[-2:] == 'ey':
            plural = singular[:-2] + "ies"
        elif singular[-1:] == 'y':
            plural = singular[:-1] + "ies"
        else:
            plural = singular + "s"
        return plural

    @classmethod
    def run_cmd(cls, cmd):
        """
        Execute a bash shell command from Python.
        Best to execute scripts using `bash` not `touch`, `.` or `sh`

        :Args:  {list} shell command as a string in a list

        :Return: {tuple} ({boolean} success/failure, {bytes} result)
        """
        cmd_rc = False
        cmd_result = b'' # Stores bytes

        if cmd == "" or cmd is None:
            cmd_rc = False
        else:
            # shell=True means cmd param contains a regular cmd string
            shell = shl.Popen(cmd, shell=True,
                              stdin=shl.PIPE, stdout=shl.PIPE, stderr=shl.STDOUT)
            cmd_result, _ = shell.communicate()
            if 'failure'.encode('utf-8') in cmd_result or 'fatal'.encode('utf-8') in cmd_result:
                cmd_rc = False
            else:
                cmd_rc = True
        return (cmd_rc, cmd_result)

    def exec_bash(self, cmd_list):
        """
        Run a series of (one or more) OS commands, displaying results to log

        :Args: {list} of strings formatted correctly as OS commands

        :Return: {string} decoded message from execution of last command in list
        """
        for cmd in cmd_list:
            _, result = self.run_cmd(cmd)
            result = result.decode('utf-8').strip()
        return result

    def get_path(self, p_path):
        """
        Validate path exists and convert it to absolute, normal and real for the environment.
        Works for directory, file, symlink or mount.

        @DEV: Consider the pathlib.Path library. It is quite a robust extension over the
              os.path library. Can probably do away with this function altogether. It doesn't
              add to the native capability and I don't think I have ever used more than one of
              the returned values in the calling object.

        :Args: {string} path to file or dir expressed in any legit notation

        :Return: {namedtuple}

        - .exists   {boolean} whether the dir or file exists
        - .rqst     {string} requested path
        - .abs      {path} absolute path using Posix syntax
        - .isDir    {boolean}
        - .isFile   {boolean}
        - .isLink   {boolean}
        - .isMount  {boolean}
        - .parent   {string} parent path
        - .item     {string} name of file or directory
        """
        path_a = False
        path_a = path.abspath(p_path)                   # .abs
        path_p = {pattr: False for pattr in ['isDir', 'isFile', 'isLink', 'isMount',
                                             'parent', 'item']}
        path_e = True if path.exists(path_a) else False     # .exists
        if path_e:
            path_p['isDir'] = True if path.isdir(p_path) else path_p['isDir']
            path_p['isFile'] = True if path.isfile(p_path) else path_p['isFile']
            path_p['isLink'] = True if path.islink(p_path) else path_p['isLink']
            path_p['isMount'] = True if path.ismount(p_path) else path_p['isMount']
            path_a = path.normpath(path.normcase(path.realpath(path_a)))    # .abs
            v_parts = path.split(path_a)
            path_p['parent'] = v_parts[0]
            path_p['item'] = v_parts[1]

        fpath = namedtuple('fpath', 'rqst exists abs isDir isFile isLink isMount parent item')
        return fpath(p_path, path_e, path_a, path_p['isDir'], path_p['isFile'], path_p['isLink'],
                     path_p['isMount'], path_p['parent'], path_p['item'])

    def get_var(self, p_varnm):
        """
        Retrieve value of an environment variable.

        :Args: {string} name of environment variable

        :Return: {tuple} (string, string)
            - (name of requested var, value of requested var or empty string)
        """
        retval = tuple()
        (rc, rslt) = self.run_cmd("echo $" + p_varnm)
        if rc:
            retval = (p_varnm, rslt.decode('UTF-8')[0:-1])
        else:
            retval = (p_varnm, '')
        return retval
