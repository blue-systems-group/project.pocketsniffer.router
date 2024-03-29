#!/usr/bin/python

import os
import sys
import time
import tempfile
import shutil
import subprocess
from datetime import datetime as dt
import pexpect
import argparse
import glob

DEFAULT_KEY = '~/.ssh/id_rsa.pub'
DEFAULT_SSID2 = "PocketSniffer2"
DEFAULT_SSID5 = "PocketSniffer5"
DEFAULT_ROOT_PASSWORD = 'jN8HhAD8'
DEFAULT_AP_PASSWORD =   'abcd1234'
DEFAULT_GATEWAY =     '192.168.1.1'
DEFAULT_TEMPLATE_DIR = './templates/'
DEFAULT_USER_NAME = 'jinghaos'
DEFAULT_USER_PASS = 'jinghaos'

HOSTNAME_PLACEHOLDER = '__hostname__'
SSID2_PLACEHOLDER = '__ssid2__'
SSID5_PLACEHOLDER = '__ssid5__'
PASSWORD_PLACEHOLDER = '__password__'
CLONEMAC_PLACEHOLDER = '__clonemac__'
PROMPT = '[#\$]'
SSH_ARGS = '-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no'
KEY_FILE_NAME = 'id_isa.pub'
DEV_PATH = '/dev/sda1'

USB_MODULES = [
'kmod-usb-core',
'kmod-usb-ohci',
'kmod-usb-uhci',
'kmod-usb2',
'kmod-usb-storage',
'kmod-fs-ext4',
'kmod-usb-storage-extras',
'usbutils',
'block-mount',
'e2fsprogs',
]

EXTRA_MODULES = [
'shadow-useradd',
'shadow-groupadd',
'shadow-usermod',
'sudo',
'python',
'iwinfo',
'hostapd-utils',
# 'python-setuptools',
'iperf',
]

parser = argparse.ArgumentParser()

parser.add_argument('--hostname', required=True, help="Hostname")

parser.add_argument('--key', default=DEFAULT_KEY, help="Public key file for ssh.")
parser.add_argument('--ssid2',  default=DEFAULT_SSID2, help="AP SSID")
parser.add_argument('--ssid5',  default=DEFAULT_SSID5, help="AP SSID")
parser.add_argument('--clonemac', type=str, help="MAC address to clone")
parser.add_argument('--rootpass', default=DEFAULT_ROOT_PASSWORD, help="Root password")
parser.add_argument('--appass', default=DEFAULT_AP_PASSWORD, help="AP password")
parser.add_argument('--gateway', default=DEFAULT_GATEWAY, help="AP gateway")
parser.add_argument('--template', default=DEFAULT_TEMPLATE_DIR, help="Configuration templates")
parser.add_argument('--user', default=DEFAULT_USER_NAME, help="Non-privileged user to create.")
parser.add_argument('--userpass', default=DEFAULT_USER_PASS, help="Password for non-privilged user")
parser.add_argument('--nosudo', action='store_true', help="Do not add user to sudo group")
parser.add_argument('--quiet', action='store_true', help="Supress verbose output.")

args = parser.parse_args()

def log(s) :
  print >>sys.stdout, '[%s] %s' % (dt.now(), s)

"""
Send a cmd to ssh session, throw exception if cmd's return code is not 0.
"""
def check_call(session, cmd, timeout=60) :
  session.sendline(cmd)
  session.expect(PROMPT, timeout=timeout)
  session.sendline('echo $?')
  match = session.expect(['\r\n0\r\n', '\r\n1\r\n'])
  session.expect(PROMPT)
  if match == 1 :
    raise Exception(str(session))

"""
Install a list of packages.
"""
def install_packages(session, pkgs) :
  check_call(session, 'opkg update')
  check_call(session, 'opkg --force-depends install %s' % (' '.join(pkgs)))

"""
Reboot router, resume ssh session after rebooting.
"""
def reboot(session, block=True) :
  global args, logfile

  log("Rebooting...")
  session.sendline('reboot')
  session.expect(PROMPT)
  session.kill(0)

  if not block :
    return

  # do not ping immediately.
  time.sleep(20)

  child = pexpect.spawn('ping %s' % (args.gateway))
  child.expect('ttl', timeout=300)

  # safety margin.
  time.sleep(10)

  child = pexpect.spawn('ssh %s root@%s' % (SSH_ARGS, args.gateway))
  child.logfile=logfile
  child.expect(PROMPT)
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
  raise Exception(str(child))


# somehow, after telnet, the router seems need a while to accept ssh requests.
time.sleep(15)



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
  raise Exception(str(child))


log("Preparing configuration files...")
try :
  template_dir = glob.glob(os.path.expanduser(args.template))[0]
except :
  raise Exception("Template dir not found: %s." % (args.template))

temp_dir = os.path.join(tempfile.mkdtemp(), 'templates')
shutil.copytree(template_dir, temp_dir)
for placeholder, sub, f in zip([HOSTNAME_PLACEHOLDER, SSID2_PLACEHOLDER, SSID5_PLACEHOLDER, PASSWORD_PLACEHOLDER],
    [args.hostname, args.ssid2, args.ssid5, args.appass], ['system', 'wireless', 'wireless', 'wireless']) :
  cmd = 'sed -i -e \'s@%s@%s@g\' %s' % (placeholder, sub, os.path.join(temp_dir, "etc/config/%s" % (f)))
  if not args.quiet :
    log(cmd)
  subprocess.check_call(cmd, stdout=logfile, stderr=logfile, shell=True)

if args.clonemac:
  cmd = 'sed -i -e \'s@%s@%s@g\' %s' % (CLONEMAC_PLACEHOLDER, args.clonemac, os.path.join(temp_dir, 'etc/init.d/clonemac'))
  subprocess.check_call(cmd, stdout=logfile, stderr=logfile, shell=True)
else:
  os.remove(os.path.join(temp_dir, 'etc/init.d/clonemac'))


log("Copying configurations files...")
subprocess.check_call('scp %s -r %s/* root@%s:/' % (SSH_ARGS, temp_dir, args.gateway),
    stdout=logfile, stderr=logfile, shell=True)


child = pexpect.spawn('ssh %s root@%s' % (SSH_ARGS, args.gateway))
child.logfile=logfile
child.expect(PROMPT)


if args.clonemac:
  check_call(child, '/etc/init.d/clonemac start')
  check_call(child, '/etc/init.d/clonemac enable')
  check_call(child, 'udhcpc -i eth1 -q')
  time.sleep(3)


log("Installing USB support...")
install_packages(child, USB_MODULES)




log("Checking %s..." % (DEV_PATH))
try :
  check_call(child, 'ls -al %s' % (DEV_PATH))
  log("USB disk %s detected." % (DEV_PATH))
except :
  log("No USB disk detected.")
  child = reboot(child)






log("Checking extroot...")
try :
  check_call(child, 'mount | grep "%s on /overlay"' % (DEV_PATH))
  log("Already using extroot.")
except :
  log("No extroot detected.")
  log("Making ext4 file system...")
  check_call(child, 'mkfs.ext4 %s' % (DEV_PATH), timeout=300)
  check_call(child, 'mkdir -p /mnt/usb')

  log("Copying existing overlay files...")
  check_call(child, 'mount %s /mnt/usb/' % (DEV_PATH))
  check_call(child, 'tar -C /overlay -cvf - . | tar -C /mnt/usb -xf -')

  child = reboot(child)

  try :
    check_call(child, 'mount | grep "%s on /overlay"' % (DEV_PATH))
  except :
    raise Exception(str(child))




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



log("Done setting up %s." % (args.hostname))
reboot(child)


log("Validating setup...")

log("Checking if user %s can login..." % (args.user))
child = pexpect.spawn('ssh %s %s@%s' % (SSH_ARGS, args.user, args.gateway))
try :
  child.expect('password')
  child.sendline(args.userpass)
  child.expect(PROMPT)
except :
  raise Exception(str(child))

log("Checking sudo...")
check_call(child, 'sudo ls /etc')

log("Checking hostname...")
check_call(child, 'hostname | grep "%s"' % (args.hostname))

log("Checking SSID...")
check_call(child, 'uci show wireless | grep "%s"' % (args.ssid))

log("Checking password...")
check_call(child, 'uci show wireless | grep "%s"' % (args.appass))

log("All good. Finish.")
