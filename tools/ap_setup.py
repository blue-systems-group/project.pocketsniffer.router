#!/usr/bin/python

import os
import sys
import pexpect
import argparse
import glob

ROOT_PASSWD = 'BM5jJBAiUaHCNFdJDUzJxdOuxi5CiLs9'
AP_PASSWD =   'LDR9OXnevs5lBlCjz0MNga2H40DlT2m0'
GATEWAY =     '192.168.1.1'

KEY_FILE_NAME = 'id_isa.pub'

"""
The authenticity of host
"""

parser = argparse.ArgumentParser()

parser.add_argument('--key', required=True, help="Public key file for ssh.")

args = parser.parse_args()


child = pexpect.spawn('telnet %s' % (GATEWAY))
match = child.expect(['Connection refused', 'root@OpenWrt:/#'])
if match == 0 :
  print "Unable to telnet, assuming you have already set up root's password."
elif match == 1 :
  print "Setting up root password..."
  child.sendline('passwd')
  child.expect('New password:')
  child.sendline(ROOT_PASSWD)
  child.expect('Retype password')
  child.sendline(ROOT_PASSWD)
  child.sendline('exit')
  child.expect(pexpect.EOF, timeout=None)

try :
  key_file = glob.glob(args.key)[0]
except :
  print "Can not find key file %s." % (args.key)
  exit(0)

child = pexpect.spawn('ssh root@%s' % (GATEWAY))
match = child.expect(['OpenWrt', 'password', 'The authenticity of host'])
if match == 2 :
  print "Deleting outdated known_hosts ..."
  subprocess.check_call('rm -fv ~/.ssh/known_hosts', shell=True)
child.kill(0)

child = pexpect.spawn('ssh root@%s' % (GATEWAY))
match = child.expect(['OpenWrt', 'password', 'The authenticity'])
if match == 0 :
  child.kill(0)
  print "Password free ssh is already enabled."
elif match == 1:
  child.kill(0)

  print "Copying key file %s ..." % (key_file)
  child = pexpect.spawn('scp %s root@%s:/tmp/%s' % (key_file, GATEWAY, KEY_FILE_NAME))
  child.expect('password')
  child.sendline(ROOT_PASSWD)
  child.expect(pexpect.EOF, timeout=None)

  print "Setting up password-free login ..."
  child = pexpect.spawn('ssh root@%s \'cat /tmp/%s > /etc/dropbear/authorized_keys\'' % (GATEWAY, KEY_FILE_NAME))
  child.expect('password')
  child.sendline(ROOT_PASSWD)
  child.expect(pexpect.EOF, timeout=None)
