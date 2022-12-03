# spam-rescore

## Motivation

`spam-rescore.py` will re-run SpamAssassin (SA) on email that has already delivered. This is useful for checks that can change based on when they're run. Savvy spammers change originating IP addresses and link URLs often, so results for RBL/URIBL tests, in particular, can change soon (~1 hour) after spam delivery.

In practice, many *near spam* messages (those with spam scores close to, but not above, the default threshold of `5.0` for SpamAssassin) will get pushed over the threshold a short time later, after the various blacklist tests have been updated. Hopefully, before end users ever see their inbox marred by a false negative.

![spam rescore metrics](https://moonspider.com/spam-rescore-metrics.png "spam rescore metrics")
<p align="center">Daily spam-rescore metrics for an installation with 2 accounts</p>

## Mechanics

* Python script
* Runs as a daemon
* Scans recent (default: last day) messages periodically (default: every 10 minutes)
* Moves messages with SA score above threshold (default: 5.0) to another folder (default: `probably-spam`)
* IMAP-based, will work with all common IMAP servers
* Supports multiple accounts
* Can be run remotely from IMAP host
* Optionally emit metrics on spam checks to Graphite / Grafana

## Setup

Checkout the code:

`$ git clone git@github.com:davebrown/spam-rescore.git && cd spam-rescore`

Install its dependencies:

`$ pip install -r requirements.txt`

You will want to set up a `$HOME/.spam-config.yaml` file in the home directory of the user running spam-rescore.py. (Aside: passing credentials on the command line is a bad idea, since they will appear in your shell history and be visible to `ps`).

```
# spamc arg: max message size, in bytes. default=2048000 (2 MB)
max-message-size: 4096000
# spamc arg: -u <username> (run as <username>, usually to pick up their Bayes filter)
spamc-as-user: true
# poll interval, in seconds. default = 5 minutes
poll-seconds: 120
# email log on CRITICAL messages, and daily stats summary of activity
email-alert: alerts@example.com
# SMTP host to use when delivering above email
mailhost: localhost
accounts:
  - email: test@example.com
    password: 's3cr3t'
  - email: test2@example.com
    password: s00p3rs3cr3t
    host: imap.example.com
    verify-ssl: false
graphiteHost: 10.1.2.3
graphitePort: 2003
```

`.spam-config.yaml` can scan multiple accounts, as above. `email` and `password` are the required fields. Most fields are self-explanatory. `verify-ssl: false` disables certificate chain validation. Not recommended, but necessary if you're using a self-signed cert.

If you're running a service that can receive metrics in graphite format, specifiy `graphiteHost` and `graphitePort` in the config file.

## Usage

Full usage of the tool, as of this writing:

**`$ ./spam-rescore.py -h`**
```
usage: spam-rescore.py [options] <command>

positional arguments:
  command               rescore | stats | list | daemon
  args                  command-specific arguments

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         emit verbose output
  -c CONFIG, --config CONFIG
                        specify config file
  -s SINCE, --since SINCE
                        examine messages since date (eg, "10d", "2w", "1m"
  --score SCORE         score filter, skip messages with score <=filter (used
                        in list,rescore,daemon). Default=0.0
  --num NUM             maximum number of messages to examine
  -m MAILBOX, --mailbox MAILBOX
                        specify mailbox
  -l LOGFILE, --logfile LOGFILE
                        specify log file (in daemon mode)
  -n, --dry-run         dry run; do not move/delete messages

analyze and re-evaluate spam profile of IMAP mailboxes
```

After setup, you can simply kick the tires on IMAP connectivity by listing an IMAP folder (say, `probably-spam`) for the last 2 weeks:

**`$ ./spam-rescore.py -m probably-spam --since 2w list`**

```
        Date               ID       Score                 From                           Subject                  Flags
===========================================================================================================================
2017-09-16 04:33:03    49774        2.9      "MONICA"                         HI                               ('\\Seen',
                                             <s213417642@nmmu.ac.za>                                           'Junk',
                                                                                                               '$Junk')
---------------------------------------------------------------------------------------------------------------------------
2017-09-17 18:00:14    49775        3.6      "Lt.Gen James L Terry"           Army Lt. Gen. James Terry        ('\\Seen',
                                             <sam@synergita.net>                                               '$NotJunk',
                                                                                                               'NotJunk')
---------------------------------------------------------------------------------------------------------------------------
2017-09-20 02:27:38    49756        4.1      Pills-from-Canada                Best medications available are   ('\\Seen',)
                                             <noreply@celebrationbowl.com>    sold at our trusted online
                                                                              pharmacy! This month at half
                                                                              price!
```

The script skips over messages with an existing SA score below a *possiblySpam* threshold, which defaults to `0.0`. The reason is that the tool is concerned with finding spam that made its way to inboxes, so it skips likely ham. You can override the *possiblySpam* threshold with the `--score` command line option.

So if you want to check connectivity with your Inbox folder, you'll probably want to use a list command with a large negative number for score threshold:

**`$ ./spam-rescore.py --score -10 --since 1w list`**

You can then **rescore** a folder, say your `spam` folder. This re-runs SA locally, on messages with an existing SA score above the *possiblySpam* threshold (again, default `0.0`). Note that `--dry-run` tells the tool **not** to move messages, or to change any folder in any way:

**`$ ./spam-rescore.py --dry-run -m spam --since 1w rescore`**
```
logged in user@example.com
searching messages since 2017-09-14 21:02:16.461241
have 4 messages in folder spam
new spam found, score changed 2.9 -> 5.8 for 9446/"HI"
new spam found, score changed 3.6 -> 11.1 for 9447/"Army Lt. Gen. James Terry"
Found 2 spam message(s), but not moving them (--dry-run specified)
OUT of 4 message(s):
 1 skipped (score below threshold of 0)
 2 new spam
 0 dropped below spam threshold
 3 score increased
 0 score decreased
 0 score unchanged
 ```
 
 Once you're happy with the basic operation, you can run it as a daemon for continual spam re-scoring and quarantine:
 
 **`$ ./spam-rescore.py daemon`**

The `daemon` command echos its PID file and log file before detaching from the terminal.

Assuming you've been using SpamAssassin a while, and you're a pack rat who saves most of your email, you can aggregated metrics of the SA scores in a mailbox with the `stats` command. E.g., over the prior 12 months for your Inbox:

**`./spam-rescore.py --since 12m --score -10 --num 2000 --mailbox INBOX stats`**

```
monthly spam score stats on INBOX
month     count     min   max   median   mean
2016-10      80    -9.4   0.6     -2.7   -3.5
2016-11     168    -9.4   1.2     -3.5   -4.1
2016-12     117    -9.6   3.2     -2.6   -3.4
2017-1      132    -9.6   0.3     -2.9   -3.3
2017-2      126   -10.1   3.8     -2.6   -3.0
2017-3      248    -9.6   2.9     -2.8   -3.0
2017-4      126   -10.1   1.1     -2.6   -2.8
2017-5       75   -10.1   1.0     -3.9   -3.7
2017-6      147    -9.6   1.0     -2.6   -3.1
2017-7       85    -9.6   1.2     -2.6   -3.1
2017-8       89    -7.8   4.9     -1.4   -1.4
2017-9      191   -10.4   1.7     -1.9   -2.4
```

## RFE

The tool suffices for the needs of the author, but some possible enhancements have been listed in the issues of this repo https://github.com/davebrown/spam-rescore/issues PR's are welcome.
