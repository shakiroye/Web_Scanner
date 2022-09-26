#!/usr/bin/env python3
# coding:utf-8
import random
import sys
import threading
import urllib
import urllib.request
import urllib.response
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse


class WebScanner:

    def __init__(self, url, proxy=None, user_agent="Mozilla/5.0 (X11; Linux i686; rv:68.0)\
    Gecko/20100101 Firefox/68.0"):
        if not url.endswith("/") and not url.endswith(".php") and not url.endswith(".html"):
            self.url = url + "/"
        else:
            self.url = url
        self.proxy = proxy
        self.user_agent = user_agent
        self.session = requests.Session()
        self.link_list = []
        self.stopped = False

    def check_sqli_form(self, page=None):
        if page is None:
            page = self.url
        source = self.get_page_source(page)
        if source is not None:
            soup = BeautifulSoup(source, "html.parser")
            forms_list = soup.find_all("form")

            payload = "'" + random.choice("abcdef")
            ret = ""
            for form in forms_list:
                form_action = form.get("action")
                form_method = form.get("method")
                target_url = urllib.parse.urljoin(page, form_action)

                input_list = form.find_all("input")
                param_list = {}

                for input_ in input_list:
                    input_name = input_.get("name")
                    input_type = input_.get("type")
                    input_value = input_.get("value")

                    if "?" + input_name not in target_url and "&" + input_name not in target_url:
                        if input_type == "text" or input_type == "password":
                            param_list[input_name] = payload
                        elif input_value is not None:
                            param_list[input_name] = input_value
                        else:
                            param_list[input_name] = ""

                    if form_method.lower() == "get":
                        res = self.session.get(target_url, params=param_list)

                    elif form_method.lower() == "post":
                        res = self.session.post(target_url, data=param_list)

                    if "You have an error in your SQL syntax;" in res.text:
                        print("INJECTION SQL DETECTEE DANS FORM : " + res.url + " (" + form_action + ")")
                        ret = ret + "INJECTION SQL DETECTEE DANS FORM : " + res.url + " (" + form_action + ")\n"

            return ret

    def check_sqli_link(self, page=None):
        if page is None:
            page = self.url
        payload = "'" + random.choice("abcdef")
        page = page.replace("=", "=" + payload)

        res = self.session.get(page)

        if "You have an error in your SQL syntax;" in res.text:
            print("INJECTION SQL DETECTEE DANS LIEN : " + res.url)
            return "INJECTION SQL DETECTEE DANS LIEN : " + res.url + "\n"
        else:
            return ""

    def check_xss_form(self, page=None):
        if page is None:
            page = self.url
        source = self.get_page_source(page)
        soup = BeautifulSoup(source, "html.parser")
        forms_list = soup.find_all("form")
        payload = "<script>alert('test');</script>"
        ret = ""
        for form in forms_list:
            form_action = form.get("action")
            form_method = form.get("method")

            input_list = form.find_all("input")
            target_url = urllib.parse.urljoin(page, form_action)
            param_list = {}
            for input_ in input_list:
                input_name = input_.get("name")
                input_type = input_.get("type")
                input_value = input_.get("value")

                if "?" + input_name not in target_url and "&" + input_name not in target_url:
                    if input_type == "text" or input_type == "password":
                        param_list[input_name] = payload
                    elif input_value is not None:
                        param_list[input_name] = input_value
                    else:
                        param_list[input_name] = ""

                if form_method.lower() == "get":
                    res = self.session.get(target_url, params=param_list)

                elif form_method.lower() == "post":
                    res = self.session.post(target_url, data=param_list)

                if payload in res.text:
                    print("XSS DETECTE DANS FORM : " + res.url + " (" + form_action + ")")
                    ret = ret + "XSS DETECTE DANS FORM : " + res.url + " (" + form_action + ")\n"
        return ret

    def check_xss_link(self, page=None):
        if page is None:
            page = self.url
        payload = "<script>alert('test');</script>"
        page = page.replace("=", "=" + payload)

        res = self.session.get(page)

        if payload in res.text:
            print("XSS DETECTE DANS LIEN : " + res.url)
            return "XSS DETECTE DANS LIEN : " + res.url + "\n"
        else:
            return ""

    def _do_check_vuln(self, queue, link_list):
        try:
            for link in link_list:
                chk_xss_link = self.check_xss_link(link)
                if chk_xss_link != "":
                    queue.put(chk_xss_link)
                chk_xss_form = self.check_xss_form(link)
                if chk_xss_form != "":
                    queue.put(chk_xss_form)
                chk_sqli_link = self.check_sqli_link(link)
                if chk_sqli_link != "":
                    queue.put(chk_sqli_link)
                chk_sqli_form = self.check_sqli_form(link)
                if chk_sqli_form != "":
                    queue.put(chk_sqli_form)
        except KeyboardInterrupt:
            print("\nProgramme arrêté par l'utilisateur.")
            sys.exit(1)
        except Exception as e:
            print("Erreur : " + str(e))
            sys.exit(1)

    def _check_vuln_end_callback(self, check_thread, check_queue):
        check_thread.join()
        check_queue.put("END")

    def check_vuln(self, check_queue, link_list):
        check_thread = threading.Thread(target=self._do_check_vuln, args=(check_queue, link_list))
        check_thread.start()
        watch_thread = threading.Thread(target=self._check_vuln_end_callback, args=(check_thread, check_queue))
        watch_thread.start()
