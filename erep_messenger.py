#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
:module:    erep_messenger.py
:class:     ErepMessenger/0  inherits object
:author:    PQ <pq_rfw @ pm.me>
:modules:   ./requirements.txt
:config:    ./db/emsg.conf
:log:       ./db/emsg.log  or (Linux only) /dev/shm/emsg.log

@DEV -
        See: https://github.com/eeriks/erepublik (GitHub)
        and: https://libraries.io/pypi/eRepublik (PyPi)
        for more up-to-date eRepublik-related Python3 code
"""
# standard
import fnmatch
import json
import logging
import re
import requests
import time
import tkinter as tk
# external / PyPi
from bs4 import BeautifulSoup as bs
from os import listdir, path
from PIL import Image, ImageTk
from pprint import pprint as pp
from tkinter import messagebox, ttk
from tornado.options import define, options
# local
from emsg_logger import EmsgLogger
# from emsg_encrypt import EmsgEncrypt - not used yet

class ErepMessenger(object):
    """
    Out-of-game mass messenger for eRepublik
    """
    def __init__(self):
        """ Initialize the erep_messenger app """
        # Get and set configuration options
        self.app_dir = None
        self.opt = None
        self.__get_options()
        self.logme = True if self.opt.log_level in ('DEBUG', 'INFO') else False
        self.__set_log()

        # Set up eRepublik sessions
        self.erep_rqst = requests.Session()
        self.erep_rqst.headers = None
        self.erep_csrf_token = None
        self.__set_erep_headers()

        self.user_profile = None
        self.user_name = None
        self.user_avatar_file = None
        self.__get_user_profile()

        # Construct the messenger app
        self.id_list = None
        self.subject = None
        self.msg_body = None
        self.id_list_file_entry = None
        self.id_file_list = None
        self.listdir_files = None
        self.current_file_name = 'profile_ids'
        self.valid_list = None
        self.status_text = None
        self.citizen_id = None
        self.citizen_name = None
        self.citizen_ix = None
        self.win_emsg = tk.Tk()  # the "root" window in tk-speak
        self.win_save = None
        self.win_load = None

        self.make_root_emsg_window()
        self.make_menus()
        self.make_status_widgets()
        self.make_profile_ids_editor()
        self.make_message_editor()

    def __get_options(self):
        """ Get login info and other settings from config file.
            Config file should be in same dir as python script.

            :Return: {DotMap?} dict of config name.values using tornado.options
        """
        ## Get config file
        app_path = path.abspath(path.realpath(__file__))
        self.app_dir = path.split(app_path)[0]
        config_file_path = path.abspath(path.join(self.app_dir, 'db/emsg.conf'))

        ## Define and assign config values
        define_options = [
            'erep_mail_id',
            'erep_pwd',
            'erep_profile_id',
            'erep_url',
            'log_level',
            'log_file',
            'persist_log_path',
            'in_mem_log_path',
            'use_in_mem_log',
            'w_title',
            'w_txt_greet',
            'w_txt_connected',
            'w_txt_disconnected',
            'w_txt_login_failed',
            'w_txt_file_loaded',
            'w_txt_sent_to',
            'w_txt_list_processed',
            'w_txt_reload',
            't_id_list_title',
            't_subject_title',
            't_body_title',
            'm_warn_title',
            'm_bad_list',
            'm_bad_id',
            'm_bad_message',
            'm_bad_connect',
            'm_verifying_ids',
            'm_ids_verified',
            'm_logged_in',
            'm_not_logged_in',
            'm_no_id_list',
            'm_no_subject',
            'm_no_msg_body',
            'm_msg_body_too_long',
            'm_msg_body_current_len',
            'w_item_sep',
            'w_file_menu',
            'w_cmd_make_list',
            'w_cmd_load_list',
            'w_cmd_save_list',
            'w_cmd_connect',
            'w_cmd_disconnect',
            'w_cmd_exit',
            'w_edit_menu',
            'w_cmd_clear_list',
            'w_cmd_verify_list',
            'w_cmd_clear_msg',
            'w_cmd_verify_msg',
            'w_send_menu',
            'w_cmd_send_to_next',
            'w_cmd_send_to_all',
            's_file_name',
            's_cancel',
            's_save',
            's_load'
        ]
        for item in define_options:
            define(item)
        options.parse_config_file(config_file_path)
        self.opt = options

    def __set_log(self):
        """ Assign log file location
            Instantiate an EmsgLogger object as self.LOG

            :Set: {object} instance of EmsgLogger class
        """
        log_file = None
        if self.opt.use_in_mem_log == 'True':
            log_file_nm = self.opt.in_mem_log_path
        else:
            log_file_nm = self.opt.persist_log_path
        log_file = path.abspath(path.join(log_file_nm, self.opt.log_file))
        self.LOG = EmsgLogger(log_file, self.opt.log_level)
        self.LOG.set_logs()
        if self.logme:
            self.LOG.write_log("INFO", "Log level: {}".format(self.opt.log_level))
            self.LOG.write_log("INFO", "Log file location: {}".format(log_file))

    def __set_erep_headers(self):
        """
        Set request headers for eRepublik calls.

        @DEV - If not using US English, modify the Accept-Language values
        @DEV - User-Agent list should probably get updated

        :Set:
          - {dict} request headers for login and logout connection to eRepublik
        """
        self.erep_rqst.headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Encoding': 'gzip,deflate,sdch',
            'Accept-Language': 'en-US,en;q=0.8',
            'Connection': 'keep-alive',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/31.0.1650.63 Chrome/31.0.1650.63 Safari/537.36'}

    def __get_user_profile(self):
        """ Retrieve profile for user from eRepublik.
            Get the user's eRepublik profile ID from config file.
            Set the user name and grab the user's avatar file.

            :Set:
            - {string} user name
            - {Pillow file object} user avatar
            - {dict} user profile data
        """
        profile_url = self.opt.erep_url + "/main/citizen-profile-json/" + self.opt.erep_profile_id
        erep_response = requests.get(profile_url)
        self.user_profile = json.loads(erep_response.text)
        self.user_name = self.user_profile["citizen"]["name"]
        avatar_link = self.user_profile["citizen"]["avatar"]
        self.user_avatar_file = Image.open(requests.get(avatar_link, stream=True).raw)
        if self.logme and self.opt.log_level == "DEBUG":
            self.LOG.write_log('DEBUG', "user_profile: {}".format(self.user_profile))

    def do_nothing(self):
        """ Used for item separators in menus """
        return True

    def load_list_file(self):
        """
        Read data from selected file and load it into the id_list widget
        """
        id_list_ix = self.id_file_list.curselection()[0]
        id_list = self.listdir_files[id_list_ix]
        with open(path.abspath(path.join(self.app_dir, "db/{}".format(id_list))), "r") as f:
            id_list_data = f.read()
        self.clear_list()
        self.id_list.insert(tk.INSERT, id_list_data)
        self.status_text.config(text = "{}{}".format(self.opt.w_txt_file_loaded, id_list))
        self.win_load.withdraw()

    def load_list_dialog(self):
        """
        Populate the profile ids list from a ".list" file stored in the db directory

        @DEV - Replace all files with an encrypted sqlite database
        """
        if self.win_load is None:
            self.win_load = tk.Toplevel()
            self.win_load.title(self.opt.w_cmd_save_list)
            self.win_load.geometry('400x325+300+200')
            load_frame = ttk.Frame(self.win_load)
            load_frame.grid(row=4, column=2)
            ttk.Label(load_frame, text=self.opt.w_cmd_load_list).grid(row=0, column=1)
            ttk.Label(load_frame, text=self.opt.s_file_name).grid(row=1, column=1, sticky=tk.W)
            self.id_file_list = tk.Listbox(load_frame, selectmode=tk.SINGLE, width=40)
            self.id_file_list.grid(row=2, column=1)
            ttk.Button(load_frame, text=self.opt.s_cancel,
                       command=self.win_load.withdraw).grid(row=4, column=1, sticky=tk.W)
            ttk.Button(load_frame, text=self.opt.s_load,
                       command=self.load_list_file).grid(row=4, column=1)
        else:
            self.win_load.deiconify()

        # Load .list file names from db directory
        self.listdir_files =\
            fnmatch.filter(listdir(path.abspath(path.join(self.app_dir, 'db'))), '*.list')
        self.id_file_list.delete(0, self.id_file_list.size())
        for file_nm in self.listdir_files:
            self.id_file_list.insert(self.listdir_files.index(file_nm) + 1, file_nm)

    def save_list_file(self):
        """
        Save the current list of Profile IDs as a file

        @DEV: Note: To pull text from tk Entry widgets,
        """
        self.current_file_name = self.id_list_file_entry.get()
        self.current_file_name = self.current_file_name.replace(" ", "_").replace("\n", "").replace("'", "_").replace(".list", "").replace(".", "_")
        self.current_file_name = "{}.list".format(self.current_file_name.lower())
        file_path = path.abspath(path.join(self.app_dir, "db/{}".format(self.current_file_name)))
        list_data = self.clean_list()
        with open(file_path, "w") as f:
            f.write(list_data)
        if self.logme:
            self.LOG.write_log('INFO', "Citizens ID .list saved at: {}".format(file_path))

        self.win_save.withdraw()

    def save_list_dialog(self):
        """
        Dialog window for saving the current list of Profile IDs as a file

        @DEV - "Toplevel" is tk-speak for creating a new window under the root app
        @DEV - After creating it once, we "withdraw" to close and then "deiconify" to restore it
        """
        if self.win_save is None:
            self.win_save = tk.Toplevel()
            self.win_save.title(self.opt.w_cmd_save_list)
            self.win_save.geometry('400x125+300+200')
            save_frame = ttk.Frame(self.win_save)
            save_frame.grid(row=3, column=2)
            ttk.Label(save_frame, text=self.opt.s_file_name).grid(row=0, column=0, sticky=tk.W)
            self.id_list_file_entry = ttk.Entry(save_frame, width=40)
            if self.current_file_name is not None:
                self.id_list_file_entry.insert(tk.INSERT, self.current_file_name)
            self.id_list_file_entry.grid(row=0, column=1)
            ttk.Button(save_frame, text=self.opt.s_cancel,
                       command=self.win_save.withdraw).grid(row=2, column=1, sticky=tk.W)
            ttk.Button(save_frame, text=self.opt.s_save,
                       command=self.save_list_file).grid(row=2, column=1)
        else:
            self.win_save.deiconify()

    def connect(self):
        """
        Login to eRepublik
        This script accepts login credentials only from a configuration file.

        @DEV - Store login credentials (and log locations) to an encrypted sqllite database.
        @DEV - Provide a GUI for managing connection credentials

        :Set: {string} CSRF token assigned after a valid login
        """
        if self.erep_csrf_token is not None:
            messagebox.showinfo(title = self.opt.m_info_title,
                                detail = self.opt.m_logged_in)
        else:
            formdata = {'citizen_email': self.opt.erep_mail_id,
                        'citizen_password': self.opt.erep_pwd,
                        "remember": '1',
                        'commit': 'Login'}
            erep_login = self.erep_rqst.post(self.opt.erep_url + "/login",
                                            data=formdata, allow_redirects=False)
            if self.logme:
                self.LOG.write_log('INFO',
                                "user login status code: {}".format(erep_login.status_code))
            if erep_login.status_code == 302:
                erep_response = self.erep_rqst.get(self.opt.erep_url)
                erep_soup = bs(erep_response.text, features="html.parser")
                soup_scripts = erep_soup.find_all("script")
                soup_script = '\n'.join(map(str, soup_scripts))
                #pylint: disable=anomalous-backslash-in-string
                regex = re.compile("csrfToken\s*:\s*\'([a-z0-9]+)\'")
                self.erep_csrf_token = regex.findall(soup_script)[0]
                self.status_text.config(text = self.opt.w_txt_connected)
                if self.logme and self.opt.log_level == 'DEBUG':
                    self.LOG.write_log('INFO', "CSRF Token:\t{}".format(self.erep_csrf_token))
                    self.LOG.write_log('INFO', "user login response:\n{}".format(soup_script))
            else:
                self.status_text.config(text = self.opt.w_txt_login_failed)

    def disconnect(self):
        """ Logout from eRepublik
        Totally guessing here.
        A 302 response here is good. But not sure if it is really terminating the user session.
        """
        formdata = {'citizen_email': self.opt.erep_mail_id,
                    'citizen_password': self.opt.erep_pwd,
                    "remember": '1',
                    'commit': 'Logout'}
        erep_logout = self.erep_rqst.post(self.opt.erep_url + "/logout",
                                           data=formdata, allow_redirects=False)
        if self.logme:
            self.LOG.write_log('INFO',
                               "user logout status code: {}".format(erep_logout.status_code))
        if erep_logout.status_code == 302:
            self.erep_csrf_token = None
            self.erep_rqst.get(self.opt.erep_url)
            self.status_text.config(text = self.opt.w_txt_disconnected)

    def exit_emsg(self):
        """
        Quit the erep_messenger app
        Logout if not already disconnected
        """
        if self.erep_csrf_token is not None:
            self.disconnect()
        self.win_emsg.quit()
        self.LOG.close_logs()

    def clear_list(self):
        """
        Wipe the ID list
        """
        self.id_list.delete(1.0, tk.END)
        self.status_text.config(text = self.opt.w_cmd_make_list)

    def clean_list(self):
        """
        Clean up the Profile ID list

        @DEV - To get text from an Entry widget define a "textvariable" param or do .get() with no indexes
        @DEV - To get text from an Text widget provide a start (word.char) and end (e.g. "tk.END") index

        :Return: {string} scrubbed version of the Profile ID List data or False
        """
        # Clean up the list
        list_data_str = self.id_list.get(1.0, tk.END).strip()
        list_data_str = list_data_str.replace(",", "\n").replace("~", "\n").replace("|", "\n")
        list_data_str = list_data_str.replace("\n\n", "\n")
        self.id_list.delete(1.0, tk.END)
        self.id_list.insert(tk.INSERT, list_data_str)

        # Reject if list is empty
        if len(list_data_str) < 1:
            messagebox.showwarning(title = self.opt.m_warn_title,
                                   message = self.opt.m_bad_list,
                                   detail = "\n{}".format(self.opt.m_no_id_list))
            return False
        else:
            return list_data_str

    def verify_list(self):
        """
        Verify the Profile ID list is OK
        """
        self.valid_list = list()
        list_data_str = self.clean_list()
        self.status_text.config(text=self.opt.m_verifying_ids)
        if list_data_str:
            # Verify that each ID has a valid profile on eRepublik
            list_data = list_data_str.splitlines()
            for profile_id in list_data:
                if "\t" in profile_id:
                    profile_id = profile_id.split("\t")[0]
                time.sleep(1)
                profile_url = self.opt.erep_url + "/main/citizen-profile-json/" + profile_id
                erep_response = requests.get(profile_url)
                # Reject list if it contains an invalid Profile ID
                if erep_response.status_code == 404:
                    messagebox.showwarning(title = self.opt.m_warn_title,
                            message = self.opt.m_bad_list,
                            detail = "\n{}".format(self.opt.m_bad_id.replace("[citizen]", profile_id)))
                    if self.logme:
                        self.LOG.write_log("WARN", "Invalid eRep Profile ID: {}".format(profile_id))
                    return False
                else:
                    # Get current name for Profile ID from eRepublik
                    citizen_profile = json.loads(erep_response.text)
                    self.valid_list.append(profile_id + "\t{}".format(citizen_profile["citizen"]["name"]))
        # Refresh the ID list, showing citizen name along with each profile
        self.status_text.config(text=self.opt.m_ids_verified)
        self.id_list.delete(1.0, tk.END)
        self.id_list.insert(tk.INSERT, "\n".join(self.valid_list))
        return True

    def clear_message(self):
        """
        Wipe the Message Subject and Body
        """
        self.subject.delete(0, tk.END)      #Entry object
        self.msg_body.delete(1.0, tk.END)   #Text object

    def verify_message(self):
        """
        Verify the Message Subject and Body are OK
        """
        bad_msg_txt = None
        # Subject (Entry object) empty
        if self.subject is None or len(self.subject.get()) == 0:
            bad_msg_txt = "\n{}".format(self.opt.m_no_subject)
        else:
            # Body (Text object) empty
            msg_body_len = len(self.msg_body.get(1.0, tk.END)) - 1
            if self.msg_body is None or msg_body_len < 1:
                bad_msg_txt = "\n{}".format(self.opt.m_no_msg_body)
            # Body too long
            elif msg_body_len > 2000:
                bad_msg_txt = "\n{}\n{}{}".format(self.opt.m_msg_body_too_long,
                                                self.opt.m_msg_body_current_len,
                                                str(msg_body_len))
        if bad_msg_txt is None:
            return True
        else:
            messagebox.showwarning(title = self.opt.m_warn_title,
                                   message = self.opt.m_bad_message,
                                   detail = bad_msg_txt)
            return False

    def verify_connect(self):
        """
        Make sure there is a connection to eRepublik
        """
        bad_message = False
        bad_msg_txt = ""
        # Not connected to eRepublik
        if self.erep_csrf_token is None:
            bad_message = True
            bad_msg_txt = "\n{}".format(self.opt.m_not_logged_in)
        if bad_message:
            messagebox.showwarning(title = self.opt.m_warn_title,
                                   message = self.opt.m_bad_connect,
                                   detail = bad_msg_txt)
            return False
        else:
            return True

    def verify_all(self):
        """
        Run all the checks before starting to send messages

        :Return: {boolean} False if checks fail else True
        """
        if self.verify_list() \
        and self.verify_message() \
        and self.verify_connect():
            return True
        else:
            return False

    def send_message(self, profile_data):
        """
        Send message to one recipient

        @DEV -
            Doesn't work due to captcha...
            "The challenge solution was incorrect"
            "sitekey":"6Lf490AUAAAAAIqP0H7DFfXF5tva00u93wxAQ--h"

        :Args: {string} citizen profile ID - tab - citizen name
        """
        # Prep message
        profile = profile_data.split("\t")
        self.citizen_id = profile[0].strip()
        self.citizen_name = profile[1].strip()
        m_sub = self.subject.get()
        m_body = self.msg_body.get(1.0, tk.END)
        m_body = m_body.replace("[citizen]", self.citizen_name)
        m_body = m_body.replace("[user]", self.user_name)
        # Send message
        msg_url = "https://www.erepublik.com/en/main/messages-compose/{}".format(self.citizen_id)
        msg_headers = {
            "Referer": msg_url,
            "X-Requested-With": "XMLHttpRequest"}
        send_message = {
            "_token": self.erep_csrf_token,
            "citizen_name": self.citizen_id,
            # "citizen_name": self.citizen_name,
            "citizen_subject": m_sub,
            "citizen_message": m_body}

        msg_response = self.erep_rqst.post(
            msg_url, data=send_message, headers=msg_headers, allow_redirects = False)
        pp(msg_response.status_code)
        pp(msg_response.text)

        self.status_text.config(text = "{}{}".format(self.opt.w_txt_sent_to, profile_data))

    def send_message_to_next(self):
        """
        Attempt to send message to next listed ID
        """
        if self.verify_all():
            self.citizen_ix = 0 if self.citizen_ix is None else self.citizen_ix + 1
            if self.citizen_ix > len(self.valid_list) - 1:
                self.status_text.config(text =\
                    "{} {}".format(self.opt.w_txt_list_processed, self.opt.w_txt_reload))
            else:
                profile_data = self.valid_list[self.citizen_ix]
                self.send_message(profile_data)

    def send_message_to_all(self):
        """
        Attempt to send message to all listed IDs
        """
        if self.verify_all():
            for profile_data in self.valid_list:
                self.citizen_ix = self.valid_list.index(profile_data)
                self.send_message(profile_data)
                time.sleep(1)

            self.status_text.config(text = self.opt.w_txt_list_processed)

    def make_root_emsg_window(self):
        """
        Construct the erep_messenger app window
        """
        self.win_emsg.title(self.opt.w_title)
        self.win_emsg.geometry('900x600+100+100')
        self.win_emsg.minsize(900,600)

    def make_menus(self):
        """
        Construct the app menus
        """
        menu_bar = tk.Menu(self.win_emsg)

        file_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label=self.opt.w_file_menu, menu=file_menu)
        file_menu.add_command(label=self.opt.w_cmd_load_list, command=self.load_list_dialog)
        file_menu.add_command(label=self.opt.w_cmd_save_list, command=self.save_list_dialog)
        file_menu.add_command(label=self.opt.w_item_sep, command=self.do_nothing)
        file_menu.add_command(label=self.opt.w_cmd_connect, command=self.connect)
        file_menu.add_command(label=self.opt.w_cmd_disconnect, command=self.disconnect)
        file_menu.add_command(label=self.opt.w_item_sep, command=self.do_nothing)
        file_menu.add_command(label=self.opt.w_cmd_exit, command=self.exit_emsg)

        edit_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label=self.opt.w_edit_menu, menu=edit_menu)
        edit_menu.add_command(label=self.opt.w_cmd_clear_list, command=self.clear_list)
        edit_menu.add_command(label=self.opt.w_cmd_verify_list, command=self.verify_list)
        edit_menu.add_command(label=self.opt.w_item_sep, command=self.do_nothing)
        edit_menu.add_command(label=self.opt.w_cmd_clear_msg, command=self.clear_message)
        edit_menu.add_command(label=self.opt.w_cmd_verify_msg, command=self.verify_message)

        send_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label=self.opt.w_send_menu, menu=send_menu)
        send_menu.add_command(label=self.opt.w_cmd_send_to_next, command=self.send_message_to_next)
        send_menu.add_command(label=self.opt.w_cmd_send_to_all, command=self.send_message_to_all)
        self.win_emsg.config(menu=menu_bar)

    def make_status_widgets(self):
        """
        Construct the status message and avatar-display
        """
        status_msg = self.opt.w_txt_greet.replace("[user]", self.user_name)
        self.status_text = ttk.Label(self.win_emsg, text=status_msg)
        self.status_text.grid(column=0, row=0)
        tk_img = ImageTk.PhotoImage(self.user_avatar_file)
        user_avatar_img = ttk.Label(self.win_emsg, image=tk_img)
        user_avatar_img.image = tk_img
        user_avatar_img.place(x=725, y=20)

    def make_profile_ids_editor(self):
        """
        Construct frame for listing profile IDs to send messages to
        """
        id_frame = ttk.Frame(self.win_emsg)
        id_frame.grid(row=4, column=0)
        ttk.Label(id_frame, text=self.opt.t_id_list_title).pack(side="top")
        scroll_id = ttk.Scrollbar(id_frame)
        scroll_id.pack(side="right", fill="y", expand=False)
        self.id_list = tk.Text(id_frame, height=28, width=40, wrap=tk.WORD, yscrollcommand=scroll_id.set)
        self.id_list.pack(side="left", fill="both", expand=True)
        scroll_id.config(command=self.id_list.yview)

    def make_message_editor(self):
        """
        Construct frame for writing message Subject and Body
        """
        msg_frame = ttk.Frame(self.win_emsg)
        msg_frame.grid(row=4, column=1)
        ttk.Label(msg_frame, text=self.opt.t_subject_title).grid(row=0, column=0, sticky=tk.W)
        self.subject = ttk.Entry(msg_frame, width=39)
        self.subject.grid(row=1, column=0)
        ttk.Label(msg_frame, text=self.opt.t_body_title).grid(row=2, column=0, sticky=tk.W)
        scroll_msg = ttk.Scrollbar(msg_frame)
        scroll_msg.grid(row=3, column=1, sticky="N,S,W")
        self.msg_body = tk.Text(msg_frame, height=23, width=44, wrap=tk.WORD, yscrollcommand=scroll_msg.set)
        self.msg_body.grid(row=3, column=0, sticky=tk.W)
        scroll_msg.config(command=self.msg_body.yview)

#======================
# Main
#======================
EM = ErepMessenger()
EM.win_emsg.mainloop()
