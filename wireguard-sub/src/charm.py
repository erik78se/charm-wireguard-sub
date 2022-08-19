#!/usr/bin/env python3
# Copyright 2022 erik
# See LICENSE file for licensing details.

""" Wireguard juju subordinate charm.

Deploys wireguard VPN and allows for configuring it via a juju action.
Uses the wgconfig library to manage the config file.

"""
from asyncore import read
import base64
from multiprocessing.dummy import shutdown
import os
from pathlib import Path
import shutil
import subprocess
import logging
import sys
import wgconfig
import wgconfig.wgexec as wgexec
from typing import Literal

from ops.charm import CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, MaintenanceStatus

import utils

logger = logging.getLogger(__name__)


class WireguardSubCharm(CharmBase):
    """Charm the service."""

    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)

        # Track the port to be able to open/close properly
        self._stored.set_default(current_listenport=None)
        self._stored.set_default(current_address=None)
        self._stored.set_default(current_ipforward=False)

        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.on.get_public_key_action, self._on_get_public_key_action)
        self.framework.observe(self.on.add_peer_action, self._on_add_peer_action)
        self.framework.observe(self.on.remove_peer_action, self._on_remove_peer_action)
        self.framework.observe(self.on.show_peers_action, self._on_show_peers_action)
        self.framework.observe(self.on.up_action, self._on_up_action)
        self.framework.observe(self.on.down_action, self._on_down_action)
        

    def _on_install(self, _):
        """
        installs
        """
        self._aptinstall()
        self._createKeys()
        self._initializeConfig()
        self.unit.status = MaintenanceStatus("Installed")

    def _on_config_changed(self, _):
        """
        Update config. Will keep any settings not managed by the charm.
        
        Using: wgconfig
        See: https://github.com/towalink/wgconfig

        """
        logger.debug("config_changed running")

        restart_required = False
        if not self._stored.current_address == self.config['address']:
            self._stored.current_address = self.config['address']
            restart_required = True

        if not self._stored.current_ipforward == self.config['ip-forward']:
            self._stored.current_ipforward = self.config['ip-forward']
            restart_required = True
        
        if not self._stored.current_listenport == self.config['listenport']:
            self._stored.current_listenport = self.config['listenport']
            restart_required = True
        
        if restart_required:
            self._configureWg0()
            # If port changes, reconfigure and restart.
            self._setPort('open')
            self._restartWireguardService()
        
        self.unit.status = ActiveStatus("Ready")

    def _configureWg0(self):
        wc = wgconfig.WGConfig('wg0')
        wc.read_file()
        # Write config
        with open('/etc/wireguard/wg0.key', 'r') as privkeyfile:
            privkey_from_file = privkeyfile.read().strip()
        # Remove old values from charm configurable items.
        try:
            wc.del_attr(None,'PrivateKey', remove_leading_comments=False)
            wc.del_attr(None,'ListenPort', remove_leading_comments=False)
            wc.del_attr(None,'Address', remove_leading_comments=False)
        except:
            logger.warning("Missing attributes in config file.")
        # Add configs we know.
        try:
            wc.add_attr(None,'PrivateKey', privkey_from_file)
            wc.add_attr(None,'ListenPort', self._stored.current_listenport)
            wc.add_attr(None,'Address', self._stored.current_address)
        except:
            logger.debug("Failed to create config, bailing out, check config values for charm. No changes were made.")
            sys.exit(1)
        
        # Write config file wg0.conf
        wc.write_file()
        os.chmod('/etc/wireguard/wg0.conf', 0o600)
        os.chmod('/etc/wireguard/wg0.key', 0o600)

    def _on_start(self, _):
        self._setPort('open')
        cmd = "sudo systemctl enable wg-quick@wg0.service --now"
        subprocess.run(cmd.split())

    def _on_stop(self, _):
        self._setPort('close')
        cmd = "sudo systemctl disable wg-quick@wg0.service --now"
        subprocess.run(cmd.split())

    def _restartWireguardService(self):
        cmd = "sudo systemctl restart wg-quick@wg0.service"
        subprocess.run(cmd.split())

    def _on_get_public_key_action(self, event):
        """
        Get public key by deriving it from the private.
        """
        key = open('/etc/wireguard/wg0.key')
        pubkey = subprocess.check_output(['wg', 'pubkey'], stdin=key, cwd='/etc/wireguard/')
        event.set_results({"public-key": pubkey.decode()})

    def _on_up_action(self, event):
        """
        Enable VPN (wq-quick up wg0)
        """
        self._on_start(None)

    def _on_down_action(self, event):
        """
        Disable VPN (wq-quick up wg0)
        """
        self._on_stop(None)

    def _initializeConfig(self):
        """
        Initialize configuration.
        """
        logger.info("Initalizing config...........")
        wc = wgconfig.WGConfig('wg0')
        wc.initialize_file('# Installed by Juju')
        wc.write_file('wg0')

    def _setPort(self, state: Literal['open', 'close']):
        """
        Open or close the port defined in config.
        """
        if not self._stored.current_listenport == self.config['listenport']:
            self._stored.current_listenport = self.config['listenport']
        if state == 'open':
            utils.open_port(self._stored.current_listenport, protocol="udp")
        else:
            utils.close_port(self._stored.current_listenport, protocol="udp")

    def _setFirewall(self, allow_deny: Literal['deny', 'allow']):
        """
        Manage the firewall (if applicable for the cloud)
        """
        if allow_deny == "allow":
            logger.info("managing firewall not supported yet.")
            # sudo ufw allow <port>/udp
            pass
        else:
            logger.info("managing firewall not supported yet.")
            # sudo ufw deny <port>/udp

    def _aptinstall(self):
        cmd = "apt -y install wireguard"
        subprocess.check_call(cmd.split())

    def _createKeys(self):
        """
        Create keys if not already created.
        Could be done with the wgconfig lib.
        """
        # umask 077; wg genkey | tee privatekey | wg pubkey > publickey 
        if not Path('/etc/wireguard/wg0.key').exists():

            with open('/etc/wireguard/wg0.key', "w+") as outfile:
                subprocess.run(['wg', 'genkey'], stdout=outfile)

            with open('/etc/wireguard/wg0.pub', "w+") as outfile:
                key = open('/etc/wireguard/wg0.key')
                subprocess.run(['wg', 'pubkey', 'wg0.key'], stdin=key, stdout=outfile, cwd='/etc/wireguard/')

    def validate_wireguard_public_key(self, value):
            """
            Verify wireguard key.
            """
            try:
                decoded_key = base64.standard_b64decode(value)
            except Exception as e:
                logger.error("Invalid wireguard key format:" + str(e))
                return False

            if not len(decoded_key) == 32:
                logger.error("Invalid wirguard key length (expected 32), bailing out")
                return False
            
            # Seems legit return True.
            return True

    def _on_add_peer_action(self, event):
        """
        Adds a peer via an action.
        Prints out an example config for remote endpoint.
        See: https://pypi.org/project/wgconfig/
        """
        # peer
        publickey = event.params.pop('publickey')

        if not self.validate_wireguard_public_key(publickey):
            event.set_results({"failed": "Public key not valid. Expect base64 encoded length 32"})
            sys.exit(1)

        wc = wgconfig.WGConfig('wg0')
        wc.read_file()
        self._restartWireguardService()
        
        # Adds all options given to us.
        try:
            wc.add_peer(publickey, '# Added by Juju action')
            for k,v in event.params.items():
                wc.add_attr(publickey, k, v)
            wc.write_file()
            event.set_results({"message": "Peer added to config. Service restarting."})
            self._restartWireguardService()
        except KeyError:
            event.set_results({"failed": "Peer exists already."})


    def _on_remove_peer_action(self, event):
        """
        Removes a peer via an action.
        See: https://pypi.org/project/wgconfig/
        """
        wc = wgconfig.WGConfig('wg0')
        wc.read_file()
        try:
            wc.del_peer(event.params['publickey'])
            wc.write_file()
        except Exception as e:
            event.set_results({"failed": "Something went wrong:" + str(e)})
            sys.exit(1)
        
        self._restartWireguardService()
        
    def _on_show_peers_action(self, event):
        """
        Shows the peers in the config.
        See: https://pypi.org/project/wgconfig/
        """
        wc = wgconfig.WGConfig('wg0')
        wc.read_file()
        event.set_results(wc.peers)

if __name__ == "__main__":
    main(WireguardSubCharm)
