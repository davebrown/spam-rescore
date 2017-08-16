#!/usr/bin/env python

import sys
import os
from datetime import datetime
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

SCORE_PAT = re.compile('.*score=([-+]?[0-9]*\.?[0-9]*).*')
REQUIRED_PAT = re.compile('.*required=([0-9]*\.?[0-9]*).*')

def scoreFromHeader(header):
  score = None
  required = None
  m = SCORE_PAT.match(header)
  if m:
    try:
      score = float(m.group(1))
    except ValueError, ve:
      warn('could not parse score float from %s' % (header))
      score = 1.0
  m = REQUIRED_PAT.match(header)
  if m:
    required = float(m.group(1))
  return score, required

class Msg:
  id = None
  date = None
  score = None
  required = None
  headers = None
  raw = None # full original object from imap client
  
  def __init__(self, id, spamHeader, dateHeader, headers):
    self.id = id
    self.score, self.required = scoreFromHeader(spamHeader)
    self.date = datetime.fromtimestamp(rfc822.mktime_tz(rfc822.parsedate_tz(dateHeader)))
    self.headers = headers
    self.data = {}

  def __str__(self):
    return '{Msg: id=%d score=%f date=%s}' % (self.id, self.score, str(self.date))

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
  nums = [ m.score for m in msgs ]
  for m in msgs:
    minval = min(minval, m.score)
    maxval = max(maxval, m.score)
  return len(msgs), minval, maxval, median(nums), mean(nums)

def iterMessages(callback, additionalFields=[]):
  args = ARGS.args
  verbose('fetch', args)
  if len(args) != 2:
    fail('usage: fetch <user>@<host> <password>')
  account = args[0].split('@')
  if len(account) != 2:
    fail('invalid email address: %s' % args[0])
  username = account[0]
  host = account[1]
  password = args[1]

  # FIXME: cert chain not trusted for some reason
  context = imapclient.create_default_context()
  context.verify_mode = ssl.CERT_NONE
  
  imap = IMAPClient(host, use_uid=True, ssl=True, ssl_context=context) # no one should ever use cleartext these days
  imap.login(username, password)
  info('logged in!')
  imap.noop()
  imap.select_folder(ARGS.mailbox)
  messageIds = imap.sort(['REVERSE ARRIVAL'])#imap.search()
  info('have %d messages in folder %s' % (len(messageIds), ARGS.mailbox))
  #print messageIds
  fields = ['BODY[HEADER]'] + additionalFields
  messages = imap.fetch(messageIds[:5], fields)
#  print messages
#  print type(messages)
  noDate = 0
  noScore = 0
  print 'got %d messages' % len(messages)
  parser = EmailParser()
  msgs = []
  for msgId, data in messages.iteritems():
    #print headers
    #print data
    rawHeaders = data['BODY[HEADER]']
    headers = parser.parsestr(rawHeaders, True)
    #print type(headers), headers.keys()
    spamHeader = headers.get('X-Spam-Status', None)
    dateHeader = headers.get('Date', None)
    receivedHeader = headers.get('Received', None)
    if receivedHeader is not None:
      verbose('Received: %s' % receivedHeader)
    #verbose('%s SCORE %s' % (dateHeader, spamHeader))
    if not dateHeader:
      noDate = noDate + 1
      continue
    if not spamHeader:
      noScore = noScore + 1
      continue
    msg = Msg(msgId, spamHeader, dateHeader, headers)
    msg['headers'] = rawHeaders
    for f in additionalFields:
      msg[f.lower()] = data[f]
      print f, '******', data[f], '******'
    msgs.append(msg)

  #print type(messages[0])
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

def cmd_rescore():
  def cback(msgs):
    print msgs
  msgs, _ = iterMessages(cback, ['BODY[TEXT]'])
  print '================'
  for m in msgs:
    print m['headers']
    print '---------------'
    print m['body[text]']
    print '==============='
  
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
  msgs, _ = iterMessages(cback)
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
      info('%s -- %s' % (m.month(), str(m)))

    for month in sorted(months.keys()):
      msgs = months[month]
      count, minval, maxval, med, avg = stats(msgs)
      info('%s : %d msgs, min=%f max=%f median=%f mean=%f' % (month, count, minval, maxval, med, avg))

  iterMessages(cback)
  
def cmd_hack():
  info('hack running')
  host, ip = hostAndIp('from sertcell.date (unknown [193.124.186.130])')
  print host, ip
  
def main():
  global ARGS
  parser = argparse.ArgumentParser(
    description='spam scores',
    epilog='figure out near-miss spam score threshold',
    usage="%(prog)s [options] <command>"
    )
  HOME = os.environ['HOME']
  parser.add_argument('-v', '--verbose', help='emit verbose output', default=False, action="store_true")
  parser.add_argument('-n', '--num', help='number of messages to examine', default=400)
  parser.add_argument('-m', '--mailbox', help='specify mailbox', default='INBOX')
  #parser.add_argument('-u', '--url', help='url of remote server', default='http://localhost:9080')
  parser.add_argument('command', help='hack | spam-score')
  parser.add_argument('args', nargs='*')
  ARGS = parser.parse_args()
  info('verbose is: ', ARGS.verbose)
  verbose("got args %s" % str(ARGS))
  cmd = ARGS.command.replace('-', '_')
  try:
    verbose('calling "cmd_' + cmd + '"')
    func = eval('cmd_' + cmd)
    verbose('evaluated to ' + str(func))
    func()
  except NameError:
    err("invalid command: '%s'" % cmd)
    if ARGS.verbose:
      traceback.print_exc()
    
if __name__ == '__main__':
  main()
    
