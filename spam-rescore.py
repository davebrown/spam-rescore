#!/usr/bin/env python

import sys
import os

from datetime import datetime, timedelta
import argparse
import traceback
from termcolor import cprint
import imapclient
from imapclient import IMAPClient
import ssl
from email.parser import Parser as EmailParser
import re
import rfc822
from collections import Counter
from subprocess import STDOUT, check_output, CalledProcessError
import yaml
from tempfile import TemporaryFile
from time import sleep
import time
from texttable import Texttable
import logging
import daemon
from daemon import pidfile

def catArgs(*args):
  return ' '.join([str(e) for e in args])

class Output(object):

  def info(self, *args):
    pass

  def warn(self, *args):
    pass

  def err(self, *args):
    pass

  def verbose(self, *args):
    pass

class TermOutput(Output):

  TTY = sys.stdout.isatty()

  def info(self, *args):
    msg = ' '.join([str(e) for e in args])
    sys.stdout.write(msg)
    sys.stdout.write('\n')
    sys.stdout.flush()

  def warn(self, *args):
    msg = ' '.join([str(e) for e in args])
    if self.TTY:
      cprint(msg, 'yellow', file=sys.stderr, attrs=['bold'], end='\n')
    else:
      sys.stderr.write(msg)
      sys.stderr.write('\n')

  def err(self, *args):
    msg = ' '.join([str(e) for e in args])
    if self.TTY:
      cprint(msg, 'red', attrs=['bold'], file=sys.stderr, end='\n')
    else:
      sys.stderr.write(msg)
      sys.stderr.write('\n')

  def verbose(self, *args):
    msg = ' '.join([str(e) for e in args])
    if not ARGS.verbose: return
    if self.TTY:
      cprint(msg, 'grey', attrs=['bold'], end='\n')
    else:
      sys.stdout.write(msg)
      sys.stdout.write('\n')
      sys.stdout.flush()
  

class LogOutput(Output):

  def __init__(self, logFile='/tmp/spam-scores.log'):
    global ARGS
    logLevel = logging.INFO
    if ARGS.verbose:
      logLevel = logging.DEBUG
    logging.basicConfig(
      format='%(asctime)s - %(name)s - %(levelname)s: %(message)s',
      filename=logFile,
      level=logLevel
    )
    self.logFile = logFile
    self.logger = logging.getLogger('spam-scores')
  
  def info(self, *args):
    self.logger.info(catArgs(*args))

  def warn(self, *args):
    self.logger.warning(catArgs(*args))

  def err(self, *args):
    self.logger.error(catArgs(*args))

  def verbose(self, *args):
    self.logger.debug(catArgs(*args))

  def __str__(self):
    return '{LogOutput file=%s}' % self.logFile

def info(*args):
  OUTPUT.info(*args)

def warn(*args):
  OUTPUT.warn(*args)

def err(*args):
  OUTPUT.err(*args)

def verbose(*args):
  OUTPUT.verbose(*args)

def fail(*args):
  msg = ' '.join([str(e) for e in args])
  OUTPUT.err('%s\nexiting...' % msg)
  sys.exit(1)
  
def _(data, name, required=True):
  ret = data.get(name, None)
  if not ret and required:
    raise Exception('missing required config field "%s"' % name)
  return ret

class Account(object):

  def __init__(self, data):
    self.email = _(data, 'email')
    self.password = _(data, 'password')
    self.host = _(data, 'host', False)
    self.probablySpam = data.get('probablySpam', 'probably-spam')
    account = self.email.split('@')
    if len(account) != 2:
      raise Exception('invalid email address "%s"' % self.email)
    self.username = account[0]
    if not self.host:
      self.host = account[1]

  def __str__(self):
    return '{Account %s username=%s host=%s}' % (self.email, self.username, self.host)
  
class Config(object):

  def __init__(self, data):
    accts = data.get('accounts', None)
    if accts is None:
      raise Exception('no accounts in config')
    self.accounts = [ Account(a) for a in accts ]

DEFAULT_CONFIG = {
  'accounts': []
}
def loadConfig(filename):
  if os.path.isfile(filename):
    with open(filename, 'r') as f:
      conf = yaml.safe_load(f)
      config = Config(conf)
  elif len(ARGS.args) == 2:
    verbose('config file %s not found, using command-line args' % filename)
    conf = DEFAULT_CONFIG
    conf['accounts'].append({'email': ARGS.args[0], 'password': ARGS.args[1] })
    config = Config(conf)
  else:
    fail('config file %s not found and email-address/password not passed on command line. -h for "help"' % filename)

  return config
  
SCORE_PAT = re.compile('.*score=([+-]?\d+\.?\d+).*')
REQUIRED_PAT = re.compile('.*required=(\d+\.?\d+).*')

def scoreFromHeader(header):
  if header is None:
    return None, None
  score = None
  required = None
  m = SCORE_PAT.match(header)
  if m:
    try:
      score = float(m.group(1))
    except ValueError, ve:
      warn('could not parse score float from %s' % (header))
      score = 1.0
  else:
    warn('no score pattern match on header: "%s", treating as 0' % header)
  m = REQUIRED_PAT.match(header)
  if m:
    required = float(m.group(1))
  return score, required

def dateFromReceivedHeader(header):
  if header:
    vals = header.split(';')
    if len(vals) == 2:
      #return datetime.fromtimestamp(rfc822.mktime_tz(rfc822.parsedate_tz(vals[1])))
      return vals[1]
  return None
  
class Msg(object):

  def __init__(self, id, spamHeader, dateHeader, headers):
    self.id = id
    self.score, self.required = scoreFromHeader(spamHeader)
    if self.score is None:
      warn('no score on msg id=%s header="%s"' % (self.id, spamHeader))
    if dateHeader:
      self.date = datetime.fromtimestamp(rfc822.mktime_tz(rfc822.parsedate_tz(dateHeader)))
    self.headers = headers
    self.data = {}
    self.flags = None

  def __str__(self):
    return '{Msg: id=%d score=%s date=%s}' % (self.id, '%.1f' % self.score if self.score is not None else 'None', str(self.date))

  def month(self):
    return '%d-%d' % (self.date.year, self.date.month)
  
  # return float-formatted string or "None"
  def scoreStr(self):
    if self.score is not None:
      return '%.1f' % self.score
    return 'None'
  
  def header(self, name):
    return self.headers.get(name, None)

  def __setitem__(self, key, item):
    self.data[key] = item

  def __getitem__(self, key):
    return self.data.get(key, None)

def mean(numbers):
  return float(sum(numbers)) / max(len(numbers), 1)
  
def median(lst):
  quotient, remainder = divmod(len(lst), 2)
  if remainder:
    return sorted(lst)[quotient]
  return sum(sorted(lst)[quotient - 1:quotient + 1]) / 2.
  
def stats(msgs):
  minval = 10.0
  maxval = -10.0
  nums = [ m.score if m.score else 0 for m in msgs ]
  for m in msgs:
    if m.score is not None:
      minval = min(minval, m.score)
      maxval = max(maxval, m.score)
  return len(msgs), minval, maxval, median(nums), mean(nums)

def moveMessages(imap, messages, toMailbox):
  # FIXME: ensure toMailbox exists
  imap.select_folder(ARGS.mailbox, readonly=False)
  ret = imap.copy(messages, toMailbox)
  info('copy returned', ret)
  ret = imap.delete_messages(messages)
  info('delete returned', ret)
  #ret = imap.expunge(messages) # FIXME: pull in IMAPClient patch
  ret = imap.expunge()
  info('expunge returned', ret)

def connectIMAP(account):
  username = account.username
  host = account.host
  password = account.password

  # FIXME: cert chain not trusted for some reason
  context = imapclient.create_default_context()
  # FIXME: verify_mode from config
  context.verify_mode = ssl.CERT_NONE
  
  imap = IMAPClient(host, use_uid=True, ssl=True, ssl_context=context) # no one should ever use cleartext these days
  imap.login(username, password)
  info('logged in %s' % account.email)
  return imap

def iterMessages(accountOrClient, additionalFields=[]):
  doLogout = True
  if isinstance(accountOrClient, IMAPClient):
    imap = accountOrClient
    doLogout = False
  else:
    imap = connectIMAP(accountOrClient)
    imap.select_folder(ARGS.mailbox)

  since = datetime.now() - timedelta(hours=24)
  info('searching messages since %s' % str(since))
  #messageIds = imap.search(['SINCE', since])
  #messageIds = imap.sort(['REVERSE DATE'])
  messageIds = imap.sort(['REVERSE DATE'], ['SINCE', since])#imap.search()
  
  info('have %d messages in folder %s' % (len(messageIds), ARGS.mailbox))
  #print messageIds
  fields = ['BODY[HEADER]'] + additionalFields
  #fields = ['ENVELOPE'] + additionalFields
  messages = imap.fetch(messageIds[:ARGS.num], fields)
  info('got %d messages' % len(messages))
  parser = EmailParser()
  msgs = []
  for msgId, data in messages.iteritems():
    rawHeaders = data['BODY[HEADER]']
    headers = parser.parsestr(rawHeaders, True)
    spamHeader = headers.get('X-Spam-Status', None)
    receivedHeader = headers.get('Received', None)
    dateHeader = headers.get('Date', dateFromReceivedHeader(receivedHeader))
    if not dateHeader:
      # not wild about this, but a bunch of other code breaks if a message has no date
      # I believe that the Received: header is generated by receiving SMTP though,
      # so I believe this won't happen
      warn('message %s/"%s" has no discernible date, ingoring' % (msgId, headers.get('Subject', None)))
      continue
    #verbose('%s SCORE %s' % (dateHeader, spamHeader))
    #if not dateHeader:
      #continue
    #if not spamHeader:
    #  noScore = noScore + 1
    #  continue
    #verbose('msgId=%s spam=%s date=%s headers=%s' % (msgId, spamHeader, dateHeader, str(headers)))
    msg = Msg(msgId, spamHeader, dateHeader, headers)
    msg['headers'] = rawHeaders
    for f in additionalFields:
      msg[f.lower()] = data[f]
    msgs.append(msg)

  msgDict = { m.id: m for m in msgs }
  messageIds = [ m.id for m in msgs ]
  flags = imap.get_flags(messageIds)
  
  for id in flags.keys():
    msgDict[id].flags = flags[id]
  if doLogout:
    imap.logout()
    info('logged out')
  return msgs

# from dortprahm.faith (unknown [23.95.188.156])  
HOST_IP_PAT = re.compile('^from (\S+) \(\S+ \[(\d+\.\d+\.\d+\.\d+)\].*')
def hostAndIp(rcvd):
  m = HOST_IP_PAT.match(rcvd)
  host = None
  ip = None
  if m:
    host = m.group(1)
    ip = m.group(2)
  return host, ip

SA_SCORE_PAT = re.compile('^([+-]?\d+\.\d+)/.*')
def run_sa(msg):
  with TemporaryFile(mode='r+b', suffix='.eml', prefix='spamcheck') as tf:
    tf.write(msg['headers'])
    tf.write(msg['body[text]'])
    tf.seek(0)
    #output = check_output(['sed', '-E', 's/score=([0-9]+\.[0-9]+)/score=3.14159/g'], stdin=tf, stderr=STDOUT)
    try:
      output = check_output(['spamc', '-c'], stdin=tf, stderr=STDOUT)
    except CalledProcessError as cpe:
      output = cpe.output.replace('\n', '')
      verbose('sa returned code=%d body="%s" for message %s' % (cpe.returncode, output, msg.id))
    m = SA_SCORE_PAT.match(output)
    if m:
      score = float(m.group(1))
      return score
    else:
      raise Exception('no score in sa output "%s"' % output)

def cmd_list():

  imap = connectIMAP(CONFIG.accounts[0])
  # open readonly b/c otherwise messages will be marked as read '\\Seen'
  imap.select_folder(ARGS.mailbox, readonly=True)
  try:
    msgs = iterMessages(imap)
    msgs = sorted(msgs, key=lambda m: m.date)
    ids = [ m.id for m in msgs ]
    table = Texttable()
    table.set_deco(Texttable.HEADER | Texttable.HLINES)
    table.header(['Date', 'ID', 'Score', 'From', 'Subject', 'Flags'])
    table.set_cols_width([20, 10, 6, 30, 30, 12])
    table.set_precision(1)
    for m in msgs:
      table.add_row([m.date, m.id, m.scoreStr(), m.headers.get('From', None), m.headers.get('Subject', None), m.flags ])
    info(table.draw())
  finally:
    imap.logout()
  
def cmd_rescore():
  for account in CONFIG.accounts:
    rescoreAccount(account)

def rescoreAccount(account):  
  info('======= RESCORE %s =========' % account.email)
  imap = connectIMAP(account)
  # FIXME: should it have per-account mailbox(es) to scan?
  imap.select_folder(ARGS.mailbox, readonly=True)
  try:
    msgs = iterMessages(imap, ['BODY[TEXT]'])
    newSpam = 0
    unSpam = 0
    scoreUp = 0
    scoreDown = 0
    scoreSame = 0
    spamIds = []
    for m in msgs:
      newScore = run_sa(m)
      subject = m.headers.get('Subject', None)
      if newScore > m.score:
        scoreUp += 1
        if newScore > 5.0:
          newSpam += 1
          spamIds.append(m.id)
          info('new spam found, score %.1f for %s/"%s"' % (newScore, m.id, subject))
      elif newScore < m.score:
        scoreDown += 1
        if m.score > 5.0 and newScore < 5.0:
          unSpam += 1
      else:
        scoreSame += 1

      if newScore != m.score:
        verbose('score went from %s to %.1f for %s/"%s"' % (m.scoreStr(), newScore, m.id, subject))
      else:
        verbose('unchanged at %s for %s/"%s"' % (m.scoreStr(), m.id, subject))

    if len(spamIds) > 0:
      info('moving %d message(s) to %s' % (len(spamIds), account.probablySpam))
      moveMessages(imap, spamIds, account.probablySpam)
    else:
      info('NO NEW SPAM found on this run (checked %d message(s))' % len(msgs))
  finally:
    imap.logout()

  info('OUT of %d message(s):' % len(msgs))
  info(' %d new spam' % newSpam)
  info(' %d dropped below spam threshold' % unSpam)
  info(' %d score increased' % scoreUp)
  info(' %d score decreased' % scoreDown)
  info(' %d score unchanged' % scoreSame)
  
def cmd_move():
  if len(ARGS.args) != 2:
    err('usage: move <msg-id> <mailbox>')
    sys.exit(1)
  msgId = ARGS.args[0]
  toMailbox = ARGS.args[1]
  imap = connectIMAP(CONFIG.accounts[0])
  # open readonly b/c otherwise messages will be marked as read '\\Seen'
  imap.select_folder(ARGS.mailbox, readonly=True)
  try:
    msgs = iterMessages(imap)
    msg = None
    for m in msgs:
      if msgId == m.headers.get('Message-Id', None):
        msg = m
        break
    if msg is None:
      fail('cannot find message id="%s" in mailbox %s' % (msgId, ARGS.mailbox))
    info('moving message %s to %s' % (str(msg), toMailbox))
    moveMessages(imap, msg.id, toMailbox)
  finally:
    imap.logout()
    
def cmd_received():
  hosts = Counter()
  ips = Counter()
  faith = { 'val': 0 }
  msgs = iterMessages(CONFIG.accounts[0])
  for m in msgs:
    rcvd = m.header('Received')
    verbose('%s rcvd: %s' % (str(m.date), rcvd))
    if 'faith' in rcvd:
      faith['val'] = faith['val'] + 1
    host, ip = hostAndIp(rcvd)
    if host is not None and ip is not None:
      hosts[host] += 1
      ips[ip] += 1
    verbose('rcvd: %s / %s' % (host, ip))
  for cnt in ips.most_common(10):
    info('%s %d' % (cnt[0], cnt[1]))
  for cnt in hosts.most_common(10):
    info('%s %d' % (cnt[0], cnt[1]))
  info('faith in %d/%d messages' % (faith['val'], len(msgs)))
  
  
def cmd_stats():
  info('cmd_stats entry')
  msgs = iterMessages(CONFIG.accounts[0])
  months = {}
  for m in msgs:
    month = months.get(m.month(), [])
    month.append(m)
    months[m.month()] = month
    #verbose('%s -- %s' % (m.month(), str(m)))

  table = Texttable()
  table.set_deco(Texttable.HEADER)
  table.set_cols_dtype(['t', 'i', 'f', 'f', 'f', 'f'])
  table.set_cols_align(['l', 'r', 'r', 'r', 'r', 'r'])
  table.set_precision(1)
  table.add_row(['month', 'count', 'min', 'max', 'median', 'mean'])
  for month in sorted(months.keys()):
    msgs = months[month]
    count, minval, maxval, med, avg = stats(msgs)
    #info('%s : %d msgs, min=%.1f max=%.1f median=%.1f mean=%.1f' % (month, count, minval, maxval, med, avg))
    table.add_row([month, count, minval, maxval, med, avg])

  info('stats\n%s' % table.draw())

def daemonLoop():
  global OUTPUT
  OUTPUT = LogOutput(ARGS.logfile)
  while True:
    try:
      info('daemon loop running at %s' % str(datetime.now()))
      cmd_rescore()
      time.sleep(10 * 60)
    except Exception as e:
      err('Exception in daemon loop', e)
      logging.error(e, exc_info=True)
      sys.exit(1)

# https://stackoverflow.com/questions/13106221/how-do-i-set-up-a-daemon-with-python-daemon/40536099#40536099  
def cmd_daemon():
  pidf = '/tmp/spam-scores.pid'
  print('starting daemon with pidfile=%s and log file=%s' % (pidf, ARGS.logfile))
  info('daemon starting....')
  with daemon.DaemonContext(pidfile=pidfile.TimeoutPIDLockFile(pidf)) as context:
    daemonLoop()
      
def cmd_hack():
  info('Info level', 'a', 'b', 'c')
  warn('Warn level', 'a', 'b', 'c')
  err('Error level', 'a', 'b', 'c', {'d': 'e', 'f': 13})
  verbose('Verbose level', 'a', 'b', 'c')
  sys.exit(1)
  
  #info('hack running')
#  host, ip = hostAndIp('from sertcell.date (unknown [193.124.186.130])')
#  print host, ip
  scoreHeader = """No, score=0.0 required=5.0 tests=BAYES_50,HTML_IMAGE_ONLY_16,
  HTML_MESSAGE,HTML_SHORT_LINK_IMG_2,RP_MATCHES_RCVD,SPF_PASS,T_DKIM_INVALID,
  URIBL_BLOCKED,URIBL_DBL_SPAM autolearn=no autolearn_force=no version=3.4.1"""
  receivedHeader = """from oiuuu3.baldnesa.cu.cc (unknown [83.167.224.177])
	by moonspider.com (Postfix) with SMTP id 3B7C3D0041
	for <dave@moonspider.com>; Thu, 16 Mar 2017 14:39:23 +0000 (UTC)"""

  print 'recvd date', dateFromReceivedHeader(receivedHeader)
  sys.exit(1)
  score, req = scoreFromHeader(scoreHeader)
  print 'score', score, 'required', req

  now = datetime.now()
  print now
  ago = now - timedelta(hours=3)
  print ago
  
  imap = connectIMAP(CONFIG.accounts[0])
  try:
    ARGS.mailbox = 'move-src'
    imap.select_folder(ARGS.mailbox)
    #print imap.capabilities()
    msgs, _ = iterMessages(imap, lambda x: None)
    print '---------------'
    #m = msgs[0]
    #print 'deleting %s/%s' % (m.id, m.headers.get('Subject', None))
    #imap.delete_messages(m.id)
    #raise Exception('deliberate break')
    m = msgs[len(msgs)-1]
    print 'moving %s/%s' % (str(m.id), m.headers.get('Subject', None))
    print 'copy -> dest:', imap.copy(m.id, 'move-dest')
    print 'delete', imap.delete_messages(m.id)
    # imap.expunge()
    imap._imap.uid('expunge', m.id)
    
    #for m in msgs:
    #  print str(m)
    #print('----------------')
    #ids = [ m.id for m in msgs ]
    #flags = imap.get_flags(ids)
    #for id in flags.keys():
    #  print id, str(flags[id])
  finally:
    imap.logout()
  

COMMANDS = [
  cmd_rescore,
  cmd_received,
  cmd_stats,
  cmd_hack,
  cmd_list,
  cmd_daemon,
  cmd_move
]

def main():
  global ARGS
  global CONFIG
  global OUTPUT
  OUTPUT = TermOutput()
  validCommands = ''
  #for c in COMMANDS:
  for c in COMMANDS:
    if validCommands != '':
      validCommands = validCommands + ' | '
    validCommands = validCommands + ' ' + c.__name__[4:].replace('_', '-')
  
  parser = argparse.ArgumentParser(
    description='spam scores',
    epilog='figure out near-miss spam score threshold',
    usage="%(prog)s [options] <command>"
    )
  HOME = os.environ['HOME']
  parser.add_argument('-v', '--verbose', help='emit verbose output', default=False, action="store_true")
  parser.add_argument('-c', '--config', help='specify config file', default='%s/.spam-config.yaml' % os.environ['HOME'])
  parser.add_argument('-n', '--num', help='number of messages to examine', default=400, type=int)
  parser.add_argument('-m', '--mailbox', help='specify mailbox', default='INBOX')
  parser.add_argument('-l', '--logfile', help='specify log file (in daemon mode)', default=os.environ['HOME'] + '/logs/spam-scores.log')
  #parser.add_argument('-d', '--daemon', help='detach from terminal and run as daemon', default=False, action='store_true')
  parser.add_argument('command', help=validCommands)
  parser.add_argument('args', nargs='*', help='command-specific arguments')
  ARGS = parser.parse_args()
  CONFIG = loadConfig(ARGS.config)
  #verbose("got args %s" % str(ARGS))
  cmd = ARGS.command.replace('-', '_')
  func = None
  for f in COMMANDS:
    if cmd == f.__name__[4:]:
      func = f
      break
  if func is None:
    fail('unrecognized command %s. valid commands are %s' % (cmd, validCommands))
  func()
    
if __name__ == '__main__':
  main()
    