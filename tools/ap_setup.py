#!/usr/bin/python

import os
import sys
import tempfile
import shutil
import subprocess
from datetime import datetime as dt
import pexpect
import argparse
import glob

DEFAULT_KEY = '~/.ssh/id_rsa.pub'
DEFAULT_SSID = "PocketSniffer"
DEFAULT_ROOT_PASSWORD = 'BM5jJBAiUaHCNFdJDUzJxdOuxi5CiLs9'
DEFAULT_AP_PASSWORD =   'LDR9OXnevs5lBlCjz0MNga2H40DlT2m0'
DEFAULT_GATEWAY =     '192.168.1.1'
DEFAULT_TEMPLATE_DIR = './templates/'
DEFAULT_USER_NAME = 'jinghaos'
DEFAULT_USER_PASS = 'jinghaos'

HOSTNAME_PLACEHOLDER = '__hostname__'
SSID_PLACEHOLDER = '__ssid__'
PASSWORD_PLACEHOLDER = '__password__'
PROMPT = '#'
SSH_ARGS = '-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no'
KEY_FILE_NAME = 'id_isa.pub'
DEV_PATH = '/dev/sda1'

USB_MODULES = ['kmod-usb-core', 'kmod-usb-ohci', 'kmod-usb-uhci', 'kmod-usb2',
    'usbutils', 'kmod-usb-storage', 'kmod-fs-ext4', 'kmod-usb-storage-extras',
    'block-mount', 'e2fsprogs']

EXTRA_MODULES = ['shadow-useradd', 'shadow-groupadd', 'shadow-usermod', 'sudo',
    'sed', 'python', 'vim', 'bash', 'git']

parser = argparse.ArgumentParser()

parser.add_argument('--hostname', required=True, help="Hostname")

parser.add_argument('--key', required=False, default=DEFAULT_KEY,
    help="Public key file for ssh.")
parser.add_argument('--ssid', required=False, default=DEFAULT_SSID,
    help="AP SSID")
parser.add_argument('--rootpass', required=False, default=DEFAULT_ROOT_PASSWORD,
    help="Root password")
parser.add_argument('--appass', required=False, default=DEFAULT_AP_PASSWORD,
    help="AP password")
parser.add_argument('--gateway', required=False, default=DEFAULT_GATEWAY,
    help="AP gateway")
parser.add_argument('--template', required=False, default=DEFAULT_TEMPLATE_DIR,
    help="Configuration templates")
parser.add_argument('--user', required=False, default=DEFAULT_USER_NAME,
    help="Non-privileged user to create.")
parser.add_argument('--userpass', required=False, default=DEFAULT_USER_PASS,
    help="Password for non-privilged user")
parser.add_argument('--nosudo', required=False, action='store_true',
    help="Do not add user to sudo group")
parser.add_argument('--quiet', required=False, action='store_true',
    help="Supress verbose output.")

args = parser.parse_args()

def log(s) :
  print >>sys.stdout, '[%s] %s' % (dt.now(), s)

"""
Send a cmd to ssh session, throw exception if cmd's return code is not 0.
"""
def check_call(session, cmd, timeout=60) :
  session.sendline(cmd)
  match = session.expect(PROMPT, timeout=timeout)
  session.sendline('echo $?')
  match = session.expect(['0', '1'])
  if match == 1 :
    raise Exception("%s failed." % (cmd))
  session.expect(PROMPT)

"""
Install a list of packages.
"""
def install_packages(session, pkgs) :
  check_call(session, 'opkg update')
  check_call(session, 'opkg install %s' % (' '.join(pkgs)))

"""
Reboot router, resume ssh session after rebooting.
"""
def reboot(session) :
  global args, logfile

  session.sendline('reboot')
  session.expect(PROMPT)
  session.kill(0)

  child = pexpect.spawn('ping %s' % (args.gateway))
  try :
    child.expect('ttl', timeout=300)
  except :
    raise Exception("Router still down after 300 seconds. Something is wrong.")

  child = pexpect.spawn('ssh %s root@%s' % (SSH_ARGS, args.gateway))
  child.logfile=logfile
  child.expect(PROMPT, timeout=None)
  return child



if args.quiet :
  logfile = open('/dev/null', 'w')
else :
  logfile = sys.stdout


log("Checking root password...")
child = pexpect.spawn('telnet %s' % (args.gateway))
child.logfile=logfile
match = child.expect([PROMPT, pexpect.EOF, pexpect.TIMEOUT])
if match == 0 :
  log("Setting up root password...")
  child.sendline('passwd')
  child.expect('password')
  child.sendline(args.rootpass)
  child.expect('password')
  child.sendline(args.rootpass)
  child.expect(PROMPT)
  child.kill(0)
elif match == 1 :
  log("Unable to telnet, assuming you have already set up root's password.")
else :
  log(str(child))
  raise Exception("%s not reachable. Check router connection." % (args.gateway))



log("Checking password-free ssh...")
child = pexpect.spawn('ssh %s root@%s' % (SSH_ARGS, args.gateway))
child.logfile=logfile
match = child.expect([PROMPT, 'password', pexpect.EOF, pexpect.TIMEOUT])
if match == 0 :
  log("Already have password-free ssh access.");
elif match == 1 :
  log("Setting up password-free ssh...")
  try :
    key_file = glob.glob(os.path.expanduser(args.key))[0]
  except :
    log("SSH public key file not found: %s" % (args.key))
    exit(0)

  child = pexpect.spawn('scp %s %s root@%s:/tmp/%s'
      % (SSH_ARGS, key_file, args.gateway, KEY_FILE_NAME))
  child.logfile=logfile
  child.expect('password')
  child.sendline(args.rootpass)
  child.expect(pexpect.EOF)

  child = pexpect.spawn('ssh %s root@%s \'cat /tmp/%s > /etc/dropbear/authorized_keys\''
      % (SSH_ARGS, args.gateway, KEY_FILE_NAME))
  child.logfile=logfile
  child.expect('password')
  child.sendline(args.rootpass)
  child.expect(pexpect.EOF)
else :
  log(str(child))
  raise Exception("Unable to ssh. Check router connection.")


log("Preparing configuration files...")
try :
  template_dir = glob.glob(os.path.expanduser(args.template))[0]
except :
  raise Exception("Template dir not found: %s." % (args.template))

temp_dir = os.path.join(tempfile.mkdtemp(), 'templates')
shutil.copytree(template_dir, temp_dir)
for placeholder, sub, f in zip([HOSTNAME_PLACEHOLDER, SSID_PLACEHOLDER, PASSWORD_PLACEHOLDER],
    [args.hostname, args.ssid, args.appass], ['system', 'wireless', 'wireless']) :
  cmd = 'sed -i -e \'s@%s@%s@g\' %s' % (placeholder, sub, os.path.join(temp_dir, "etc/config/%s" % (f)))
  if not args.quiet :
    log(cmd)
  subprocess.check_call(cmd, stdout=logfile, stderr=logfile, shell=True)


log("Copying configurations files...")
subprocess.check_call('scp %s -r %s/* root@%s:/' % (SSH_ARGS, temp_dir, args.gateway),
      stdout=logfile, stderr=logfile, shell=True)


log("Installing USB support...")
child = pexpect.spawn('ssh %s root@%s' % (SSH_ARGS, args.gateway))
child.logfile=logfile
child.expect(PROMPT)
install_packages(child, USB_MODULES)



log("Checking %s..." % (DEV_PATH))
try :
  check_call(child, 'ls -al %s' % (DEV_PATH))
  log("USB disk %s detected." % (DEV_PATH))
except :
  log("No USB disk detected, try rebooting...")
  child = reboot(child)




log("Checking extroot...")
try :
  check_call(child, 'mount | grep "%s on /overlay"' % (DEV_PATH))
  log("Already using extroot.")
except :
  log("No extroot detected. Creating...")
  log("Making ext4 file system...")
  check_call(child, 'mkfs.ext4 %s' % (DEV_PATH), timeout=120)
  check_call('mkdir -p /mnt/usb')

  log("Copying existing overlay files...")
  check_call('mount -t ext4 %s /mnt/usb' % (DEV_PATH))
  check_call('tar -C /overlay -cvf - . | tar -C /mnt/usb -xf -')

  child = reboot(child)

  try :
    check_call(child, 'mount | grep "%s on /overlay"' % (DEV_PATH))
  except :
    log(str(child))
    raise Exception("No USB partition detected, extroot failed.")



log("Installing packages...")
install_packages(child, EXTRA_MODULES)



log("Checking sudo group...")
try :
  check_call(child, 'cat /etc/group | grep "sudo"')
  log("sudo group exists.")
except :
  log("Creating sudo group...")
  check_call(child, 'groupadd --system sudo')

try :
  check_call(child, 'sed -i -e \'s@^# %sudo.*$@%sudo ALL=(ALL) NOPASSWD: ALL@\' /etc/sudoers')
except :
  pass



log("Checking user %s..." % (args.user))
try :
  check_call(child, 'cat /etc/passwd | grep "%s"' % (args.user))
  log("User %s exists." % (args.user))
except :
  log("Creating user %s..." % (args.user))
  check_call(child, 'useradd %s' % (args.user))
  child.sendline('passwd %s' % (args.user))
  child.expect('password')
  child.sendline(args.userpass)
  child.expect('password')
  child.sendline(args.userpass)
  child.expect(PROMPT)

try :
  check_call(child, 'sed -i -e \'/^%s/ s@:$@:/bin/bash@\' /etc/passwd' % (args.user))
  check_call(child, 'mkdir -p /home/%s' % (args.user))
  if not args.nosudo :
    check_call(child, 'usermod -a -G sudo %s' % (args.user))
except :
  pass



log("Done setting up %s. Rebooting..." % (args.hostname))
child = reboot(child)
child.kill(0)
log("Complete.")
