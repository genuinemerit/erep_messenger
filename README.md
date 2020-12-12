# erep_messenger

This is a friendly attempt to fork an old version of this tool: https://pypi.org/project/ErepMessenger/, then:
  - Upgrading to Python3
  - Using newer versions of Tk, BeautifulSoup, etc.
  - More up-to-date Python syntax

Development and testing so far only on Ubuntu 20.04.1 LTS 64-bit.

Seems to "work" as designed, except that eRep now uses Captcha checks for sending messages and have not been able to come up with a way to automate or bypass that.

## package and environment

- Not packaged up. No setup.py defined.
- Requires python3.
- See requirements.txt for required modules.

## How to

- Update db/emsg.conf with credentials
- python3 erep_messenger.py
