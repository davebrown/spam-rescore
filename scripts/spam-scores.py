#!/usr/bin/env python

import sys
import os

# import imapclient from dev
#sys.path.insert(0, '/Users/dave/code/imapclient/imapclient')
# import imaplib locally
#dir_path = os.path.dirname(os.path.realpath(__file__))
#sys.path.insert(0, dir_path)

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
from texttable import Texttable
import logging

logging.basicConfig(
  format='%(asctime)s - %(levelname)s: %(message)s',
  level=logging.DEBUG
)

TTY = sys.stdout.isatty()

def info(*args):
  msg = ' '.join([str(e) for e in args])
  sys.stdout.write(msg)
  sys.stdout.write('\n')
  sys.stdout.flush()

def warn(*args):
  msg = ' '.join([str(e) for e in args])
  if TTY:
    cprint(msg, 'yellow', file=sys.stderr, attrs=['bold'], end='\n')
  else:
    sys.stderr.write(msg)
    sys.stderr.write('\n')

def err(*args):
  msg = ' '.join([str(e) for e in args])
  if TTY:
    cprint(msg, 'red', attrs=['bold'], file=sys.stderr, end='\n')
  else:
    sys.stderr.write(msg)
    sys.stderr.write('\n')

def fail(*args):
  msg = ' '.join([str(e) for e in args])
  err('%s\nexiting...' % msg)
  sys.exit(1)
  
def verbose(*args):
  msg = ' '.join([str(e) for e in args])
  #print('  (...verbose entry "%s"...)' % msg)
  if not ARGS.verbose: return
  if TTY:
    cprint(msg, 'grey', attrs=['bold'], end='\n')
  else:
    sys.stdout.write(msg)
    sys.stdout.write('\n')
    sys.stdout.flush()

def _(data, name, required=True):
  ret = data.get(name, None)
  if not ret and required:
    raise Exception('missing required config field "%s"' % name)
  return ret

class Account(object):
  email = None
  username = None
  password = None
  host = None
  disableCert = False

  def __init__(self, data):
    self.email = _(data, 'email')
    self.password = _(data, 'password')
    self.host = _(data, 'host', False)
    account = self.email.split('@')
    if len(account) != 2:
      raise Exception('invalid email address "%s"' % self.email)
    self.username = account[0]
    if not self.host:
      self.host = account[1]

  def __str__(self):
    return '{Account %s username=%s host=%s}' % (self.email, self.username, self.host)
  
class Config(object):
  accounts = None

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
    warn('no score pattern match on header: "%s"' % header)
  m = REQUIRED_PAT.match(header)
  if m:
    required = float(m.group(1))
  return score, required

class Msg(object):
  id = None
  date = None
  score = None
  required = None
  headers = None
  raw = None # full original object from imap client
  flags = None
  def __init__(self, id, spamHeader, dateHeader, headers):
    self.id = id
    self.score, self.required = scoreFromHeader(spamHeader)
    if self.score is None:
      warn('no score on msg id=%s header="%s"' % (self.id, spamHeader))
    self.date = datetime.fromtimestamp(rfc822.mktime_tz(rfc822.parsedate_tz(dateHeader)))
    self.headers = headers
    self.data = {}

  def __str__(self):
    return '{Msg: id=%d score=%s date=%s}' % (self.id, '%.1f' % self.score if self.score is not None else 'None', str(self.date))

  def month(self):
    return '%d-%d' % (self.date.year, self.date.month)

  def header(self,name):
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

def connectIMAP(account):
  username = account.username
  host = account.host
  password = account.password

  # FIXME: cert chain not trusted for some reason
  context = imapclient.create_default_context()
  context.verify_mode = ssl.CERT_NONE
  
  imap = IMAPClient(host, use_uid=True, ssl=True, ssl_context=context) # no one should ever use cleartext these days
  imap.login(username, password)
  info('logged in %s' % account.email)
  return imap

def iterMessages(accountOrClient, callback, additionalFields=[]):
  doLogout = True
  if isinstance(accountOrClient, IMAPClient):
    imap = accountOrClient
    doLogout = False
  else:
    imap = connectIMAP(accountOrClient)
    imap.select_folder(ARGS.mailbox)

  since = datetime.now() - timedelta(hours=24)
  verbose('searching messages since %s' % str(since))
  #messageIds = imap.search(['SINCE', since])
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
    dateHeader = headers.get('Date', None)
    receivedHeader = headers.get('Received', None)
    #verbose('%s SCORE %s' % (dateHeader, spamHeader))
    #if not dateHeader:
      #continue
    #if not spamHeader:
    #  noScore = noScore + 1
    #  continue
    msg = Msg(msgId, spamHeader, dateHeader, headers)
    msg['headers'] = rawHeaders
    for f in additionalFields:
      msg[f.lower()] = data[f]
    msgs.append(msg)

  msgDict = { m.id: m for m in msgs }
   
  flags = imap.get_flags(messageIds)
  for id in flags.keys():
    msgDict[id].flags = flags[id]
  if doLogout:
    imap.logout()
  info('logged out')
  ret = callback(msgs)
  return msgs, ret 

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
  def cback(msgs):
    pass

  imap = connectIMAP(CONFIG.accounts[0])
  # open readonly b/c otherwise messages will be marked as read '\\Seen'
  imap.select_folder(ARGS.mailbox, readonly=True)
  try:
    msgs, _ = iterMessages(imap, cback)
    msgs = sorted(msgs, key=lambda m: m.date)
    ids = [ m.id for m in msgs ]
    table = Texttable()
    table.set_deco(Texttable.HEADER | Texttable.HLINES)
    table.header(['Date', 'ID', 'Score', 'From', 'Subject', 'Flags'])
    table.set_cols_width([20, 10, 6, 30, 30, 12])
    table.set_precision(1)
    for m in msgs:
      table.add_row([m.date, m.id, '%.1f' % m.score if m.score is not None else 'None', m.headers.get('From', None), m.headers.get('Subject', None), m.flags ])
    info(table.draw())
  finally:
    imap.logout()
  
def cmd_rescore():
  def cback(msgs):
    print msgs
  msgs, _ = iterMessages(CONFIG.accounts[0], cback, ['BODY[TEXT]'])
  print '================'
  newSpam = 0
  unSpam = 0
  scoreUp = 0
  scoreDown = 0
  scoreSame = 0
  for m in msgs:
    #headers = m['headers']
    #print headers
    #print '---------------'
    #print m['body[text]']
    #print '==============='
    newScore = run_sa(m)
    if newScore > m.score:
      scoreUp += 1
      if newScore > 5.0:
        newSpam += 1
    elif newScore < m.score:
      scoreDown += 1
      if m.score > 5.0 and newScore < 5.0:
        unSpam += 1
    else:
      scoreSame += 1
    subject = m.headers.get('Subject', None)
    info('score went from %.1f to %.1f for %s/"%s"' % (m.score, newScore, m.id, subject))
  info('OUT of %d message(s):' % ARGS.num)
  info(' %d new spam' % newSpam)
  info(' %d dropped below spam threshold' % unSpam)
  info(' %d score increased' % scoreUp)
  info(' %d score decreased' % scoreDown)
  info(' %d score unchanged' % scoreSame)
  
def cmd_received():
  hosts = Counter()
  ips = Counter()
  faith = { 'val': 0 }
  def cback(msgs):
    print 'faith is', faith
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
  msgs, _ = iterMessages(CONFIG.accounts[0], cback)
  for cnt in ips.most_common(10):
    info('%s %d' % (cnt[0], cnt[1]))
  for cnt in hosts.most_common(10):
    info('%s %d' % (cnt[0], cnt[1]))
  info('faith in %d/%d messages' % (faith['val'], len(msgs)))
  
  
def cmd_stats():
  def cback(msgs):
    months = {}
    for m in msgs:
      month = months.get(m.month(), [])
      month.append(m)
      months[m.month()] = month
      verbose('%s -- %s' % (m.month(), str(m)))

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
    info(table.draw())
  iterMessages(CONFIG.accounts[0], cback)
  
def cmd_hack():
  info('hack running')
#  host, ip = hostAndIp('from sertcell.date (unknown [193.124.186.130])')
#  print host, ip
  scoreHeader = """No, score=0.0 required=5.0 tests=BAYES_50,HTML_IMAGE_ONLY_16,
  HTML_MESSAGE,HTML_SHORT_LINK_IMG_2,RP_MATCHES_RCVD,SPF_PASS,T_DKIM_INVALID,
  URIBL_BLOCKED,URIBL_DBL_SPAM autolearn=no autolearn_force=no version=3.4.1"""
  score, req = scoreFromHeader(scoreHeader)
  print 'score', score, 'required', req

  now = datetime.now()
  print now
  ago = now - timedelta(hours=3)
  print ago
  sys.exit(1)
  
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
  cmd_list
]

def main():
  global ARGS
  global CONFIG
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
  #parser.add_argument('-u', '--url', help='url of remote server', default='http://localhost:9080')
  parser.add_argument('command', help=validCommands)
  parser.add_argument('args', nargs='*', help='command-specific arguments')
  ARGS = parser.parse_args()
  CONFIG = loadConfig(ARGS.config)
  info('verbose is: ', ARGS.verbose)
  verbose("got args %s" % str(ARGS))
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
    
