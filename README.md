# SynackBot

This is a modified and rewritten version of the python synackAPI project [https://github.com/gexpose/synackAPI](https://github.com/gexpose/synackAPI) with a bot wrapper around combining all the example from the repo. Also this code is designed to be installable as python module through pip for example.

# Installation

SynackBot itself does not need to be installed. Just execute `synackbot.py`.
However, there are a few dependencies. They are listed in the
[requirements.txt](https://github.com/patrickhener/synackbot/blob/master/requirements.txt).
Install them either via `pip3 install --user -r requirements.txt` or use a
virtual environment.

If you do want to install SynackBot, you should do `pip3 install --user .` or `python setup.py install`.

Python2 is not supported.

venv
----

`venv` can be installed on Debian-like systems by `apt install
python3-venv`.

Run `python3 -m venv env` to create a virtual environment, then use `source
env/bin/activate` to activate it. Now run `pip3 install --user .`
to install the depencendies inside the virtual environment.


# Configuration

There is a sample file which needs to be put under `~/.synack/synack.conf`:

```
[DEFAULT]
poll_sleep = 10
login_wait = 15
login_url = https://login.synack.com
email = your@email.com
password = Your-Secure-Password
authy_secret = Your-Authy-Key
telegram_key = Your-Telegram-Bot-Api-Key
telegram_chat = Your-Bot-ChatID
proxy = False
proxy_port = 8080
```

The fields are mostly self-explanatory.

## Basics

You at least need to fill in your login email address your login password and the authy key.

To get the authy key follow [these instructions](https://gist.github.com/gboudreau/94bb0c11a6209c82418d01a59d958c93).

## Notifications

Notifications are handled with telegram. Be sure to have your telegram account ready.

- Create a new bot with BotFather
- Send initial message to your bot
- Retrieve the correct chat id by using this curl request:

```bash
> curl -sk "https://api.telegram.org/bot<api_token>/getUpdates" | jq
{
  "ok": true,
  "result": [
    {
      "update_id": 165114930,
      "message": {
        "message_id": 3,
        "from": {
          "id": <you want this number>,
          "is_bot": false,
          "first_name": "Patrick",
          "username": "myusernameredacted",
          "language_code": "en"
        },
        "chat": {
          "id": <you want this number>,
          "first_name": "Patrick",
          "username": "myusernameredacted",
          "type": "private"
        },
        "date": 1653999524,
        "text": "test"
      }
    }
  ]
}
```

The result should show a message with a chat id called `id`.

Use your `api_token`as `telegram_key` and your and the `id` as `telegram_chat` in `synack.conf`.

# Usage

```
┌──(patrick㉿kali)-[~/synackAPI]
└─$ ./synackbot.py -h
usage: synackbot.py [-h] [-v] [-d] [-H | -a | -s | -t | -T] [-c CODENAME]

Synack API request and bot implementation

options:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -d, --debug           Activate debug logging
  -H, --hydra           Pull hydra results (combined with 'codename')
  -a, --analytics       Download analytics (combined with 'codename')
  -s, --scope           Download scope (combined with 'codename')
  -t, --target          Reads current target or sets it when combined with 'codename'
  -T, --transactions    Display transaction overview
  -c CODENAME, --codename CODENAME
                        Target codename
```

If you just call it without any arguments it will start the forever loop and do the following actions over and over again:

- Sleep for the amount of `poll_time` (in seconds)
- Check for new notifications
  - if there are any notifications regarding missions or vulnerabilities it will send you a notification
  - Then it will mark all notifications as read
- Check for new messages (conversation)
  - if there are any new ones it will send you a notification and mark it as read
- Register all not yet registered targets
  - if any new were registered you will get a notification with quite a detail on the newly registered target
- Poll for new missions
  - if any new missions are released it tries to claim as long as your claim limit is not reached
  - if a mission is claimes successfully you will get a notification with quite a detail on the newly claimed mission
- Then start over again


## One-Shot Actions

While running the forever loop you could use the tool in a second terminal window and run one of the available "one-shot" actions:

- Download hydra for target
- Download analytics for target
- Download scope for target
- Display your current selected target
- Change your target
- Display your earnings

