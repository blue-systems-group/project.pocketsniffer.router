import socket
import json
import logging
import subprocess

from common import RequestHandler
from collector import parse_dhcp_leases
import utils
import settings


logger = logging.getLogger('pocketsniffer')


def iface_enabled(iface):
  return iface in subprocess.check_output('iwinfo', shell=True)


class APConfigHandler(RequestHandler):

  def handle(self):
    need_restart_wifi = False
    for idx, band in [(0, 'band2g'), (1, 'band5g')]:
      if band not in self.request:
        continue

      band_config = self.request[band]
      if 'enable' in band_config:
        if not band_config['enable']:
          if iface_enabled('wlan%d' % (idx)):
            logger.debug("Disabling %s" % (band))
            subprocess.check_call('uci set wireless.radio%d.disabled=1' % (idx), shell=True)
            need_restart_wifi = True
          else:
            logger.debug("%s is already disabled." % (band))
            continue
        else:
          if not iface_enabled('wlan%d' % (idx)):
            logger.debug("Enabling %s" % (band))
            subprocess.check_call('uci set wireless.radio%d.disabled=0' % (idx), shell=True)
            need_restart_wifi = True
          else:
            logger.debug("%s is already enabled." % (band))

      if 'channel' in band_config:
        try:
          current_channel = int(subprocess.check_output('uci show wireless.radio%d.channel' % (idx), shell=True).split('=')[1])
        except:
          current_channel = None
        if current_channel is not None and band_config['channel'] == current_channel:
          logger.debug("%s already in channel %d." % (band, current_channel))
        else:
          logger.debug("Switching %s channel to %d" % (band, band_config['channel']))
          subprocess.check_call('uci set wireless.radio%d.channel=%d' % (idx, band_config['channel']), shell=True)
          if iface_enabled('wlan%d' % (idx)):
            try:
              subprocess.check_call('hostapd_cli -i wlan%d chan_switch 1 %d' % (idx, utils.channel2freq(band_config['channel'])), shell=True)
            except:
              need_restart_wifi = True

      if 'txpower' in band_config:
        try:
          current_txpower = int(subprocess.check_output('uci show wireless.radio%d.txpower' % (idx), shell=True).split('=')[1])
        except:
          current_txpower = None
        if current_txpower is not None and band_config['txpower'] == current_txpower:
          logger.debug("%s's txpower is already %d dBm." % (band, current_txpower))
        else:
          subprocess.check_call('uci set wireless.radio%d.txpower=%d' % (idx, band_config['txpower']), shell=True)
          logger.debug("Setting %s txpower to %d dBm" % (band, band_config['txpower']))
          if iface_enabled('wlan%d' % (idx)):
            subprocess.check_call('iw phy%d set txpower fixed %d' % (idx, band_config['txpower']*100), shell=True)

    subprocess.check_call('uci commit', shell=True)
    if need_restart_wifi:
      subprocess.check_call('wifi', shell=True)



class ClientReasocHandler(RequestHandler):

  def handle(self):
    stations = parse_dhcp_leases()
    if self.request['client'] not in stations:
      logger.error("Client %d does not exist.")
      return

    client_ip = stations[self.request['client']]

    try:
      conn = socket.create_connection((client_ip, settings.CLIENT_TCP_PORT), settings.CONNECTION_TIMEOUT_SEC*1000)
      conn.sendall(json.dumps(self.request))
      conn.close()
    except:
      logger.exception("Failed to forward message to client.")
