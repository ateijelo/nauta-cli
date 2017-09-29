#!/usr/bin/env python3

from pprint import pprint

import subprocess
import requests
import argparse
import json
import time
import bs4
import sys
import dbm
import os
import re

import logging

CONFIG_DIR = os.path.expanduser("~/.local/share/nauta/")
try:
    os.makedirs(CONFIG_DIR)
except FileExistsError:
    pass
CARDS_DB = os.path.join(CONFIG_DIR, "cards")
ATTR_UUID_FILE = os.path.join(CONFIG_DIR, "attribute_uuid")
LOGOUT_URL_FILE = os.path.join(CONFIG_DIR, "logout_url")
logfile = open(os.path.join(CONFIG_DIR, "connections.log"), "a")

#logging.basicConfig() # you need to initialize logging, otherwise you will not see anything from requests
#logging.getLogger().setLevel(logging.DEBUG)
#requests_log = logging.getLogger("requests.packages.urllib3")
#requests_log.setLevel(logging.DEBUG)
#requests_log.propagate = True

def log(*args, **kwargs):
    date = subprocess.check_output("date").decode().strip()
    kwargs.update(dict(file=logfile))
    print(
        "{:.3f} ({})".format(
            time.time(),
            date,
        ),
        *args,
        **kwargs,
    )
    logfile.flush()

def get_inputs(form_soup):
    form = {}
    for i in form_soup.find_all("input"):
        try:
            form[i["name"]] = i["value"]
        except KeyError:
            continue
    return form

def parse_time(t):
    try:
        h,m,s = [int(x.strip()) for x in t.split(":")]
        return h * 3600 + m * 60 + s
    except:
        return 0

def select_card():
    cards = []
    with dbm.open(CARDS_DB) as cards_db:
        for card in cards_db.keys():
            info = json.loads(cards_db[card].decode())
            tl = parse_time(info.get('time_left', '00:00:00'))
            if tl <= 0:
                continue
            info['username'] = card
            cards.append(info)
    cards.sort(key=lambda c: c['time_left'])
    if len(cards) == 0:
        return None, None
    return cards[0]['username'], cards[0]['password']

def up():
    session = requests.Session()
    r = session.get("http://google.com")

    soup = bs4.BeautifulSoup(r.text, 'html.parser')
    action = soup.form["action"]
    if ('google.com' in ''.join(r.cookies.list_domains()) and
        not 'secure.etecsa.net' in action):
        print("Looks like you're already connected. Use 'nauta down' to log out.")
        return

    username, password = select_card()
    if username is None:
        print("No card available, add one with 'nauta cards add'")
        return

    username = username.decode()
    tl = time_left(username)
    print("Using card {}. Time left: {}".format(username, tl))
    log("Connecting with card {}. Time left on card: {}".format(username, tl))

    form = get_inputs(soup)

    #pprint("Calling session.post:")
    #pprint({"action": action,
    #        "form": form})
    r = session.post(action, form)

    soup = bs4.BeautifulSoup(r.text, 'html.parser')
    #pprint("-------soup------")
    #pprint(soup)
    form_soup = soup.find("form", id="formulario")
    #pprint("-------form_soup------")
    #pprint(form_soup)
    action = form_soup["action"]
    #pprint("-------action------")
    #pprint(action)
    form = get_inputs(form_soup)
    #print("form:", form)
    form['username'] = username
    form['password'] = password
    csrfhw = form['CSRFHW']
    wlanuserip = form['wlanuserip']
    last_attribute_uuid = ""
    try:
        last_attribute_uuid = open(ATTR_UUID_FILE, "r").read().strip()
    except FileNotFoundError:
        pass

    guessed_logout_url = (
        "https://secure.etecsa.net:8443/LogoutServlet?" +
        "CSRFHW={}&" +
        "username={}&" +
        "ATTRIBUTE_UUID={}&" +
        "wlanuserip={}"
    ).format(
        csrfhw,
        username,
        last_attribute_uuid,
        wlanuserip
    )
    with open(LOGOUT_URL_FILE, "w") as f:
        f.write(guessed_logout_url + "\n")

    log("Attempting connection. Guessed logout url:", guessed_logout_url)
    #pprint("Calling session.post:")
    #pprint({"action": action,
    #        "form": form})
    try:
        r = session.post(action, form)
        m = re.search(r'ATTRIBUTE_UUID=(\w+)&CSRFHW=', r.text)
        attribute_uuid = None
        if m:
            attribute_uuid = m.group(1)
    except:
        attribute_uuid = None

    if attribute_uuid is None:
        print("Log in failed :(")
    else:
        with open(ATTR_UUID_FILE, "w") as f:
            f.write(attribute_uuid + "\n")
        login_time = int(time.time())
        logout_url = (
            "https://secure.etecsa.net:8443/LogoutServlet?" +
            "CSRFHW={}&" +
            "username={}&" +
            "ATTRIBUTE_UUID={}&" +
            "wlanuserip={}"
        ).format(
            csrfhw,
            username,
            attribute_uuid,
            wlanuserip
        )
        with open(LOGOUT_URL_FILE, "w") as f:
            f.write(logout_url + "\n")
        print("Logged in successfully. To logout, run 'nauta down'")
        print("or just hit Ctrl+C here, I'll stick around...")
        log("Connected. Actual logout URL is: '{}'".format(logout_url))
        if logout_url == guessed_logout_url:
            log("Guessed it right ;)")
        else:
            log("Bad guess :(")
        try:
            while True:
                print("\rConnection time: {} ".format(
                    human_secs(int(time.time()) - login_time)
                ), end="")
                time.sleep(1)
                if not os.path.exists(LOGOUT_URL_FILE):
                    break
        except KeyboardInterrupt:
            print("Got a Ctrl+C, logging out...")
            log("Got Ctrl+C. Attempting disconnect...")
            r = session.get(logout_url)
            print(r.text)

            now = int(time.time())
            log("Response to logout request: '{}'".format(r.text))
            log("Connection time:", human_secs(now - login_time))

            tl = time_left(username)
            print("Reported time left:", tl)
            log("Reported time left:", tl)

def human_secs(secs):
    return "{:02.0f}:{:02.0f}:{:02.0f}".format(
        secs // 3600,
        (secs % 3600) // 60,
        secs % 60,
    )

def down():
    try:
        logout_url = open(LOGOUT_URL_FILE).read().strip()
    except FileNotFoundError:
        print("Connection seems to be down already. To connect, use 'nauta up'")
        return
    session = requests.Session()
    print("Logging out...")
    r = session.get(logout_url)
    print(r.text)
    if 'SUCCESS' in r.text:
        os.remove(LOGOUT_URL_FILE)


def usertime(username):
    session = requests.Session()
    r = session.get("https://secure.etecsa.net:8443/EtecsaQueryServlet?op=getLeftTime&op1={}".format(username))
    return r.text

def time_left(username):
    now = time.time()
    with dbm.open(CARDS_DB, "c") as cards_db:
        card_info = json.loads(cards_db[username].decode())
        last_update = card_info.get('last_update', 0)
        if now - last_update > 60:
            time_left = usertime(username)
            last_update = time.time()
            if re.match(r'[0-9:]+', time_left):
                card_info['time_left'] = time_left
                card_info['last_update'] = last_update
                cards_db[username] = json.dumps(card_info)
        time_left = card_info.get('time_left', '-')
        return time_left

def cards(args):
    with dbm.open(CARDS_DB, "c") as cards_db:
        for card in cards_db.keys():
            card = card.decode()
            card_info = json.loads(cards_db[card].decode())
            password = card_info['password']
            password = "*" * (len(password) - 4) + password[-4:]
            print("{}\t{}\t{}".format(card, password, time_left(card)))

def newcard(username, password):
    with dbm.open(CARDS_DB, "c") as cards_db:
        cards_db[username] = json.dumps({
            'password': password,
        })

def askforcard():
    username = input("Username: ")
    password = input("Password: ")
    return username, password

def purge_cards():
    cards_to_purge = []
    with dbm.open(CARDS_DB, "c") as cards_db:
        for card in cards_db.keys():
            info = json.loads(cards_db[card].decode())
            tl = parse_time(info.get('time_left'))
            if tl == 0:
                cards_to_purge.append(card)
    delete_cards(cards_to_purge)

def delete_cards(cards):
    with dbm.open(CARDS_DB, "c") as cards_db:
        if len(cards) > 0:
            print("Will delete these cards:")
            for card in cards:
                print("  ", str(card))
            sys.stdout.flush()
            while True:
                reply = input("Proceed (y/n)? ")
                if reply.lower().startswith("y"):
                    for card in cards:
                        del cards_db[card]
                    break
                if reply.lower().startswith("n"):
                    break

def main(args):
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    status_parser = subparsers.add_parser('status')
    status_parser.set_defaults(func=status)

    cards_parser = subparsers.add_parser('cards')
    cards_parser.set_defaults(func=cards)
    cards_parser.add_argument("-v",
        action="store_true",
        help="show full passwords"
    )
    cards_subparser = cards_parser.add_subparsers()
    cards_add_parser = cards_subparser.add_parser('add')
    cards_add_parser.set_defaults(func=cards_add)
    cards_add_parser.add_argument('card', nargs="?")

    cards_clean_parser = cards_subparser.add_parser('clean')
    cards_clean_parser.set_defaults(func=cards_clean)

    cards_rm_parser = cards_subparser.add_parser('rm')
    cards_rm_parser.set_defaults(func=cards_rm)
    cards_rm_parser.add_argument('card')

    up_parser = subparsers.add_parser('up')
    up_parser.set_defaults(func=up)

    down_parser = subparsers.add_parser('down')
    down_parser.set_defaults(func=down)

    args = parser.parse_args()
    args.func(args)

    if len(args) == 0:
        args = ["status"]

    if args[0] == "up":
        up()

    if args[0] == "down":
        down()

    if args[0] == "cards":
        if len(args) > 1:
            if args[1] in ("add", "new"):
                newcard(*askforcard())
            if args[1] == "clean":
                purge_cards()
            if args[1] == "rm":
                delete_cards(args[2:])
        else:
            cards()
            select_card()

if __name__ == "__main__":
    main(sys.argv[1:])


#809bb22296c155ee7f0cbcd69113ee5dd72025294c800570
