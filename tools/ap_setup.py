#!/usr/bin/python

import os
import sys
import tempfile
from datetime import datetime as dt
import pexpect
import argparse
import glob
import pxssh
import getpass

DEFAULT_KEY = '~/.ssh/id_isa.pub'
DEFAULT_SSID = "PocketSniffer"
DEFAULT_ROOT_PASSWORD = 'BM5jJBAiUaHCNFdJDUzJxdOuxi5CiLs9'
DEFAULT_AP_PASSWORD =   'LDR9OXnevs5lBlCjz0MNga2H40DlT2m0'
DEFAULT_GATEWAY =     '192.168.1.1'
DEFAULT_TEMPLATE_DIR = glob.glob('./templates/')[0]
DEFAULT_USER_NAME = 'jinghaos'
DEFAULT_USER_PASS = 'jinghaos'

HOSTNAME_PLACEHOLDER = '__hostname__'
SSID_PLACEHOLDER = '__ssid__'
PASSWORD_PLACEHOLDER = '__password__'
PROMPT = '#'
SSH_ARGS = '-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no'
KEY_FILE_NAME = 'id_isa.pub'
DEV_PATH = '/dev/sda1'

parser = argparse.ArgumentParser()

parser.add_argument('--hostname', required=True, help="Hostname")

parser.add_argument('--key', required=False, default=DEFAULT_KEY, help="Public key file for ssh.")
parser.add_argument('--ssid', required=False, default=DEFAULT_SSID, help="AP SSID")
parser.add_argument('--rootpass', required=False, default=DEFAULT_ROOT_PASSWORD, help="Root password")
parser.add_argument('--appass', required=False, default=DEFAULT_AP_PASSWORD, help="AP password")
parser.add_argument('--gateway', required=False, default=DEFAULT_GATEWAY, help="AP gateway")
parser.add_argument('--template', required=Fasle, default=DEFAULT_TEMPLATE_DIR, help="Configuration templates")
parser.add_argument('--user', required=False, default=DEFAULT_USER_NAME, help="Non-privileged user to create.")
parser.add_argument('--userpass', required=False, default=DEFAULT_USER_PASS, help="Password for non-privilged user")
parser.add_argument('--nosudo', required=False, action='store_true', help="Do not add user to sudo group")

args = parser.parse_args()

def log(s) :
  print >>sys.stdout, '[%s] %s' % (dt.now(), s)


log("Checking telnet...")
child = pexpect.spawn('telnet %s' % (args.gateway))
try :
  match = child.expect(['Connection refused', PROMPT])
  if match == 0 :
    log("Unable to telnet, assuming you have already set up root's password.")
  else :
    log("Setting up root password...")
    child.sendline('passwd')
    child.expect('New password:')
    child.sendline(args.rootpass)
    child.expect('Retype password')
    child.sendline(args.rootpass)
    child.expect(PROMPT)

  child.kill(0)
except :
  log("telnet timeout. Please check router connection.")
  log(str(child))
  exit(0)



log("Checking password-free ssh...")
child = pexpect.spawn('ssh %s root@%s' % (SSH_ARGS, args.gateway))
try :
  match = child.expect([PROMPT, 'password'], timeout=10)
  child.kill(0)
  if match == 0 :
    log("Already have password-free ssh access.");
  else :
    try :
      key_file = glob.glob(args.key)[0]
    except :
      log("SSH public key file not found: %s." % (args.key))
      exit(0)

    log("Copying key file %s ..." % (key_file))
    child = pexpect.spawn('scp %s %s root@%s:/tmp/%s' % (SSH_ARGS, key_file, args.gateway, KEY_FILE_NAME))
    child.expect('password')
    child.sendline(args.rootpass)
    child.expect(pexpect.EOF)

    log("Setting up password-free login ...")
    child = pexpect.spawn('ssh %s root@%s \'cat /tmp/%s > /etc/dropbear/authorized_keys\'' % (SSH_ARGS, args.gateway, KEY_FILE_NAME))
    child.expect('password')
    child.sendline(args.rootpass)
    child.expect(pexpect.EOF)
except :
  log("ssh timeout.")
  log(str(child))
  exit(0)


try :
  template_dir = glob.glob(args.template)[0]
except :
  log("Template dir not found: %s." % (args.template))
  exit(0)

log("Making config files...")
temp_dir = os.path.join(tempfile.mkdtemp(), 'templates')
shutil.copytree(template_dir, temp_dir)
try :
  subprocess.check_call('sed -i -e \'s/%s/%s/g\' %s' % (HOSTNAME_PLACEHOLDER, args.hostname, os.path.join(temp_dir, "etc/config/system")))
  subprocess.check_call('sed -i -e \'s/%s/%s/g\' %s' % (SSID_PLACEHOLDER, args.ssid, os.path.join(temp_dir, "etc/config/wireless")))
  subprocess.check_call('sed -i -e \'s/%s/%s/g\' %s' % (PASSWORD_PLACEHOLDER, args.appass, os.path.join(temp_dir, "etc/config/wireless")))
except :
  log("Failed to make config file.")
  exit(0)


log("Overriding configurations files...")
child = pexpect.spawn('scp %s -r %s/* root@%s:/' % (SSH_ARGS, temp_dir, args.gateway))
child.expect(pexpect.EOF)


log("Installing USB support...")
child = pexpect.spawn('ssh %s root@%s' % (SSH_ARGS, args.gateway))
child.expect(PROMPT)
child.sendline('opkg update')
child.expect(PROMPT)
child.sendline('opkg install kmod-usb-core kmod-usb-ohci kmod-usb-uhci kmod-usb2 usbutils kmod-usb-storage kmod-fs-ext4 kmod-usb-storage-extra block-mount e2fsprogs')
child.expect(PROMPT)
child.sendline('ls -al %s' % (DEV_PATH))
try :
  child.expect(DEV_PATH)
  child.expect(PROMPT)
except :
  log("No USB disk detected. Aborting...")
  child.kill(0)
  exit(0)

log("Checking extroot...")
child.sendline('df -h')
match = child.expect([DEV_PATH, PROMPT])
if match == 0 :
  log("Already in extroot.")
else :
  log("Making ext4 file system...")
  child.sendline('mkfs.ext4 %s' % (DEV_PATH))
  child.expect(PROMPT)
  child.sendline('mkdir -p /mnt/usb')
  child.expect(PROMPT)

  log("Copying existing overlay files...")
  child.sendline('mount -t ext4 %s /mnt/usb' % (DEV_PATH))
  child.expect(PROMPT)
  child.sendline('tar -C /overlay -cvf - . | tar -C /mnt/usb -xf -')
  child.expect(PROMPT)

  child.sendline('reboot')
  child.kill(0)

  child = pexpect.spawn('ping %s' % (args.gateway))
  try :
    child.expect('ttl', timeout=30)
    child.kill(0)
  except :
    log("Router still down after 30 seconds. Something is wrong.")
    exit(0)

child = pexpect.spawn('ssh %s root@%s' % (SSH_ARGS, args.gateway))
child.expect(PROMPT)
child.sendline('df -h')
try :
  child.expect(DEV_PATH)
  child.expect(PROMPT)
except :
  log("No USB partition detected, extroot failed.")
  exit(0)

log("Installing packages...")
child.sendline('opkg update')
child.expect(PROMPT)
child.sendline('opkg install shadow-useradd shadow-groupadd shadow-usermod sudo sed python vim bash coreutils-* shadow-userdel')
child.expect(PROMPT)




log("Checking sudo group...")
child.sendline('cat /etc/group')
match = child.expect(['sudo', PROMPT])
if match == 0 :
  log("sudo group exists.")
  child.expect(PROMPT)
else :
  log("Creating sudo group...")
  child.sendline('groupadd --system sudo')
  child.expect(PROMPT)
  child.sendline('sed -i -e \'s@^#\%sudo.*$@\%sudo ALL=(ALL) NOPASSWD: ALL/\' /etc/sudoers')
  child.expect(PROMPT)




log("Checking non-privileged user %s..." % (args.user))
child.sendline('cat /etc/passwd')
match = child.expect([args.user, PROMPT])
if match == 0 :
  log("User %s already exists.")
  child.expect(PROMPT)
else :
  log("Creating user %s..." % (args.user))
  child.sendline('useradd %s' % (args.user))
  child.expect(PROMPT)
  child.sendline('passwd %s' % (args.user))
  child.expect('password')
  child.sendline(args.userpass)
  child.expect('password')
  child.sendline(args.userpass)
  child.expect(PROMPT)
  child.sendline('sed -i -e \'/^%s/ s@:$@:/bin/bash/\' /etc/passwd')
  child.expect(PROMPT)
  child.sendline('mkdir -p /home/%s' % (args.user))
  child.expect(PROMPT)
  if not args.nosudo :
    child.sendline('usermod -a -G sudo %s' % (args.user))
    child.expect(PROMPT)
