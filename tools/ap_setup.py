#!/usr/bin/python

import os
import pexpect

ROOT_PASSWD = 'BM5jJBAiUaHCNFdJDUzJxdOuxi5CiLs9'
AP_PASSWD =   'LDR9OXnevs5lBlCjz0MNga2H40DlT2m0'
GATEWAY =     '192.168.1.1'

"""
The authenticity of host
"""

"""
Set up root password.
"""
child = pexpect.spawn('telnet 192.168.1.1')
child.expect('root@OpenWrt:/#')
child.sendline('passwd')
child.expect('New password:')
child.sendline(ROOT_PASSWD)
child.expect('Retype password')
child.sendline(ROOT_PASSWD)
child.sendline('exit')
