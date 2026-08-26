# Copyright (C) 2026 The GoBGP Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import base64
import collections
import ipaddress
import json
import sys
import time
import unittest

collections.Callable = collections.abc.Callable


from lib import base
from lib.base import (
    BGP_FSM_ESTABLISHED,
    BGPContainer,
    assert_several_times,
    local,
)
from lib.gobgp import GoBGPContainer
from lib.noseplugin import parser_option


INITIAL_SECRET = b'tcp-ao-scenario-initial'
ROTATION_SECRET = b'tcp-ao-scenario-rotation'
NETSHOOT_IMAGE = 'nicolaka/netshoot:v0.15'
VRF_BIND_INTERFACE = 'vrf-ao'
DYNAMIC_NEIGHBOR_PREFIX = '172.17.0.0/16'
TCP_AO_TIMERS = {
    'connect-retry': 1,
    'hold-time': 9,
    'keepalive-interval': 1,
    'idle-hold-time-after-reset': 1,
}


def _netshoot(ctn, cmd):
    return local('docker run --rm --privileged=true --net container:{0} '
                 '{1} {2}'.format(ctn.docker_name(), NETSHOOT_IMAGE, cmd),
                 capture=True)


def _setup_vrf_device(ctn, table_id):
    subnet = ipaddress.ip_network(ctn.ip_addrs[0][1], strict=False)

    # The osrg/quagga-based test image has an old iproute2 that cannot create
    # VRF devices. Run netshoot in the same network namespace and use its
    # iproute2 instead.
    _netshoot(ctn, 'ip link add {0} type vrf table {1}'.format(
        VRF_BIND_INTERFACE,
        table_id,
    ))
    _netshoot(ctn, 'ip link set dev {0} up'.format(VRF_BIND_INTERFACE))
    _netshoot(ctn, 'ip link set dev eth0 master {0}'.format(
        VRF_BIND_INTERFACE,
    ))
    _netshoot(ctn, 'ip route replace table {0} {1} dev eth0'.format(
        table_id,
        subnet,
    ))


def _key(send_id, receive_id, algorithm, secret):
    return {
        'config': {
            'key-id': send_id,
            'receive-id': receive_id,
            'crypto-algorithm': algorithm,
            'secret-key': base64.b64encode(secret).decode('ascii'),
        },
    }


def _keychain(name, keys):
    return {'config': {'name': name}, 'keys': keys}


def _tcp_ao_config(name, preferred_send_id):
    return {
        'keychain': name,
        'preferred-send-id': preferred_send_id,
    }


def _tcp_ao_keys(ctn, peer):
    if isinstance(peer, str):
        neighbor = json.loads(ctn.local(
            'gobgp -j neighbor {0}'.format(peer), capture=True))
    else:
        neighbor = ctn.get_neighbor(peer)
    state = neighbor['state']['tcp_ao_state']
    return {key['send_id']: key for key in state['keys']}


def _assert_selected_key(test, ctn, peer, send_id, expected_ids):
    def f():
        keys = _tcp_ao_keys(ctn, peer)
        test.assertEqual(set(expected_ids), set(keys))
        test.assertTrue(keys[send_id].get('current', False))
        test.assertTrue(keys[send_id].get('receive_next', False))

    assert_several_times(f, t=10, s=1)


def _reload_tcp_ao_config(ctn, peer, name, keys, preferred_send_id):
    ctn.bgp_config['keychains'] = [_keychain(name, keys)]
    ctn.peers[peer]['tcp_ao']['preferred-send-id'] = preferred_send_id
    ctn.create_config()
    ctn.reload_config()


def _reload_keychain(ctn, name, keys):
    ctn.bgp_config['keychains'] = [_keychain(name, keys)]
    ctn.create_config()
    ctn.reload_config()


def _wait_dynamic_established(ctn, peer_addr):
    def f():
        peer = json.loads(ctn.local(
            'gobgp -j neighbor {0}'.format(peer_addr), capture=True))
        if peer['state']['session_state'] != 6:
            raise AssertionError

    assert_several_times(f, t=120, s=1)


class GoBGPTCPAOTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        base.TEST_PREFIX = parser_option.test_prefix

        g1_keys = [_key(10, 20, 'hmac_sha_1_96', INITIAL_SECRET)]
        g2_keys = [_key(20, 10, 'hmac_sha_1_96', INITIAL_SECRET)]
        g1 = GoBGPContainer(
            name='ao-g1', asn=65000, router_id='192.168.0.1',
            ctn_image_name=parser_option.gobgp_image,
            log_level=parser_option.gobgp_log_level,
            bgp_config={'keychains': [
                _keychain('g1-chain', g1_keys),
            ]})
        g2 = GoBGPContainer(
            name='ao-g2', asn=65001, router_id='192.168.0.2',
            ctn_image_name=parser_option.gobgp_image,
            log_level=parser_option.gobgp_log_level,
            bgp_config={'keychains': [
                _keychain('g2-chain', g2_keys),
            ]})

        time.sleep(max(g1.run(), g2.run()))
        g1.add_peer(g2, tcp_ao=_tcp_ao_config('g1-chain', 10),
                    timers=TCP_AO_TIMERS)
        g2.add_peer(g1, passive=True,
                    tcp_ao=_tcp_ao_config('g2-chain', 20),
                    timers=TCP_AO_TIMERS)

        cls.g1 = g1
        cls.g2 = g2
        cls.g1_keys = g1_keys
        cls.g2_keys = g2_keys

    def _wait_established(self):
        self.g1.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.g2)
        self.g2.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.g1)

    def _rotate(self, algorithm, g1_id, g2_id):
        previous_g1_id = g1_id - 1
        previous_g2_id = g2_id - 1
        self.g1_keys.append(
            _key(g1_id, g2_id, algorithm, ROTATION_SECRET))
        self.g2_keys.append(
            _key(g2_id, g1_id, algorithm, ROTATION_SECRET))

        # Change both preferred send IDs and wait for the kernel handover to
        # make the new keys current in both directions.
        _reload_tcp_ao_config(
            self.g1, self.g2, 'g1-chain', self.g1_keys, g1_id)
        _reload_tcp_ao_config(
            self.g2, self.g1, 'g2-chain', self.g2_keys, g2_id)
        _assert_selected_key(
            self, self.g1, self.g2, g1_id, [previous_g1_id, g1_id])
        _assert_selected_key(
            self, self.g2, self.g1, g2_id, [previous_g2_id, g2_id])

        # Reconnect with both key generations installed to exercise both the
        # active dial and passive accept paths with the new preferred key.
        self.g1.stop_gobgp()
        self.g1.start_gobgp()
        self._wait_established()
        _assert_selected_key(
            self, self.g1, self.g2, g1_id, [previous_g1_id, g1_id])
        _assert_selected_key(
            self, self.g2, self.g1, g2_id, [previous_g2_id, g2_id])

        flops = (
            self.g1.get_neighbor(self.g2)['state'].get('flops', 0),
            self.g2.get_neighbor(self.g1)['state'].get('flops', 0),
        )
        self.g1_keys = self.g1_keys[-1:]
        self.g2_keys = self.g2_keys[-1:]
        _reload_tcp_ao_config(
            self.g1, self.g2, 'g1-chain', self.g1_keys, g1_id)
        _reload_tcp_ao_config(
            self.g2, self.g1, 'g2-chain', self.g2_keys, g2_id)
        _assert_selected_key(self, self.g1, self.g2, g1_id, [g1_id])
        _assert_selected_key(self, self.g2, self.g1, g2_id, [g2_id])
        self.assertEqual(flops, (
            self.g1.get_neighbor(self.g2)['state'].get('flops', 0),
            self.g2.get_neighbor(self.g1)['state'].get('flops', 0),
        ))

    def test_01_peering_and_key_rotation(self):
        self._wait_established()
        _assert_selected_key(self, self.g1, self.g2, 10, [10])
        _assert_selected_key(self, self.g2, self.g1, 20, [20])

        # Rotate through every additional algorithm profile. Each transition
        # verifies live handover, reconnect, and removal of the previous key.
        for algorithm, g1_id, g2_id in [
            ('aes_128_cmac_96', 11, 21),
            ('hmac_sha_256_96', 12, 22),
            ('hmac_sha_256_128', 13, 23),
        ]:
            self._rotate(algorithm, g1_id, g2_id)


class GoBGPTCPAODynamicNeighborTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        base.TEST_PREFIX = parser_option.test_prefix

        g1_keys = [_key(10, 20, 'hmac_sha_1_96', INITIAL_SECRET)]
        g2_keys = [_key(20, 10, 'hmac_sha_1_96', INITIAL_SECRET)]
        g1 = GoBGPContainer(
            name='ao-dynamic-g1', asn=65000, router_id='192.168.0.1',
            ctn_image_name=parser_option.gobgp_image,
            log_level=parser_option.gobgp_log_level,
            bgp_config={
                'keychains': [_keychain('g1-dynamic-chain', g1_keys)],
                'peer-groups': [{
                    'config': {
                        'peer-group-name': 'ao-dynamic-group',
                        'peer-as': 65001,
                    },
                    'tcp-ao': {'config': _tcp_ao_config(
                        'g1-dynamic-chain', 10)},
                    'timers': {'config': TCP_AO_TIMERS},
                }],
                'dynamic-neighbors': [{
                    'config': {
                        'prefix': DYNAMIC_NEIGHBOR_PREFIX,
                        'peer-group': 'ao-dynamic-group',
                    },
                }],
            })
        g2 = GoBGPContainer(
            name='ao-dynamic-g2', asn=65001, router_id='192.168.0.2',
            ctn_image_name=parser_option.gobgp_image,
            log_level=parser_option.gobgp_log_level,
            bgp_config={'keychains': [
                _keychain('g2-dynamic-chain', g2_keys),
            ]})

        time.sleep(max(g1.run(), g2.run()))
        g2.add_peer(g1, tcp_ao=_tcp_ao_config('g2-dynamic-chain', 20),
                    timers=TCP_AO_TIMERS)

        cls.g1 = g1
        cls.g2 = g2
        cls.g1_keys = g1_keys
        cls.g2_keys = g2_keys
        cls.g2_addr = g2.ip_addrs[0][1].split('/')[0]

    def _wait_established(self):
        self.g2.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.g1)
        _wait_dynamic_established(self.g1, self.g2_addr)

    def test_01_peering_and_key_rotation(self):
        self._wait_established()
        _assert_selected_key(self, self.g1, self.g2_addr, 10, [10])
        _assert_selected_key(self, self.g2, self.g1, 20, [20])

        # Add the next MKT to the dynamic prefix and the active peer before
        # either side starts requesting it.
        self.g1_keys.append(
            _key(11, 21, 'aes_128_cmac_96', ROTATION_SECRET))
        self.g2_keys.append(
            _key(21, 11, 'aes_128_cmac_96', ROTATION_SECRET))
        _reload_keychain(self.g1, 'g1-dynamic-chain', self.g1_keys)
        _reload_keychain(self.g2, 'g2-dynamic-chain', self.g2_keys)

        # Rotate the preferred IDs. Updating the peer group changes existing
        # dynamic sockets in place; it does not replace the listener prefix.
        self.g1.bgp_config['peer-groups'][0][
            'tcp-ao']['config']['preferred-send-id'] = 11
        self.g1.create_config()
        self.g1.reload_config()
        _reload_tcp_ao_config(
            self.g2, self.g1, 'g2-dynamic-chain', self.g2_keys, 21)
        _assert_selected_key(self, self.g1, self.g2_addr, 11, [10, 11])
        _assert_selected_key(self, self.g2, self.g1, 21, [20, 21])

        # Remove the previous generation and reconnect. The new connection
        # proves that the dynamic listener prefix was updated as well as the
        # already established socket.
        self.g1_keys = self.g1_keys[-1:]
        self.g2_keys = self.g2_keys[-1:]
        _reload_keychain(self.g1, 'g1-dynamic-chain', self.g1_keys)
        _reload_keychain(self.g2, 'g2-dynamic-chain', self.g2_keys)
        _assert_selected_key(self, self.g1, self.g2_addr, 11, [11])
        _assert_selected_key(self, self.g2, self.g1, 21, [21])

        self.g2.stop_gobgp()
        self.g2.start_gobgp()
        self._wait_established()
        _assert_selected_key(self, self.g1, self.g2_addr, 11, [11])
        _assert_selected_key(self, self.g2, self.g1, 21, [21])


class GoBGPTCPAOVRFTest(unittest.TestCase):

    def test_01_logical_vrf_peering(self):
        base.TEST_PREFIX = parser_option.test_prefix
        g1 = GoBGPContainer(
            name='ao-vrf-g1', asn=65000, router_id='192.168.0.1',
            ctn_image_name=parser_option.gobgp_image,
            log_level=parser_option.gobgp_log_level,
            bgp_config={
                'keychains': [_keychain('g1-vrf-chain', [
                    _key(10, 20, 'hmac_sha_1_96', INITIAL_SECRET),
                ])],
                'vrfs': [{'config': {
                    'name': 'blue',
                    'rd': '65000:100',
                    'both-rt-list': ['65000:100'],
                }}],
            })
        g2 = GoBGPContainer(
            name='ao-vrf-g2', asn=65001, router_id='192.168.0.2',
            ctn_image_name=parser_option.gobgp_image,
            log_level=parser_option.gobgp_log_level,
            bgp_config={
                'keychains': [_keychain('g2-vrf-chain', [
                    _key(20, 10, 'hmac_sha_1_96', INITIAL_SECRET),
                ])],
                'vrfs': [{'config': {
                    'name': 'blue',
                    'rd': '65001:100',
                    'both-rt-list': ['65001:100'],
                }}],
            })

        time.sleep(max(g1.run(), g2.run()))
        g1.add_peer(g2, vrf='blue',
                    tcp_ao=_tcp_ao_config('g1-vrf-chain', 10),
                    timers=TCP_AO_TIMERS)
        g2.add_peer(g1, vrf='blue', passive=True,
                    tcp_ao=_tcp_ao_config('g2-vrf-chain', 20),
                    timers=TCP_AO_TIMERS)

        g1.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=g2)
        g2.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=g1)
        _assert_selected_key(self, g1, g2, 10, [10])
        _assert_selected_key(self, g2, g1, 20, [20])

    def test_02_linux_vrf_device_peering(self):
        base.TEST_PREFIX = parser_option.test_prefix
        g1_keys = [_key(10, 20, 'hmac_sha_1_96', INITIAL_SECRET)]
        g2_keys = [_key(20, 10, 'hmac_sha_1_96', INITIAL_SECRET)]
        g1 = GoBGPContainer(
            name='ao-bind-vrf-g1', asn=65000, router_id='192.168.0.1',
            ctn_image_name=parser_option.gobgp_image,
            log_level=parser_option.gobgp_log_level,
            bgp_config={
                'global': {'config': {
                    'bind-to-device': VRF_BIND_INTERFACE,
                }},
                'keychains': [_keychain('g1-vrf-chain', g1_keys)],
            })
        g2 = GoBGPContainer(
            name='ao-bind-vrf-g2', asn=65001, router_id='192.168.0.2',
            ctn_image_name=parser_option.gobgp_image,
            log_level=parser_option.gobgp_log_level,
            bgp_config={
                'global': {'config': {
                    'bind-to-device': VRF_BIND_INTERFACE,
                }},
                'keychains': [_keychain('g2-vrf-chain', g2_keys)],
            })

        time.sleep(max(BGPContainer.run(ctn) for ctn in [g1, g2]))
        _setup_vrf_device(g1, 1010)
        _setup_vrf_device(g2, 2020)
        g1.start_gobgp()
        g2.start_gobgp()
        g1.add_peer(
            g2, passive=True, bind_interface=VRF_BIND_INTERFACE,
            tcp_ao=_tcp_ao_config('g1-vrf-chain', 10),
            timers=TCP_AO_TIMERS)
        g2.add_peer(
            g1, bind_interface=VRF_BIND_INTERFACE,
            tcp_ao=_tcp_ao_config('g2-vrf-chain', 20),
            timers=TCP_AO_TIMERS)

        g1.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=g2)
        g2.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=g1)
        _assert_selected_key(self, g1, g2, 10, [10])
        _assert_selected_key(self, g2, g1, 20, [20])

        g1_keys.append(_key(11, 21, 'hmac_sha_1_96', ROTATION_SECRET))
        g2_keys.append(_key(21, 11, 'hmac_sha_1_96', ROTATION_SECRET))
        _reload_tcp_ao_config(g1, g2, 'g1-vrf-chain', g1_keys, 11)
        _reload_tcp_ao_config(g2, g1, 'g2-vrf-chain', g2_keys, 21)
        _assert_selected_key(self, g1, g2, 11, [10, 11])
        _assert_selected_key(self, g2, g1, 21, [20, 21])

        # Linux currently fails to remove VRF-scoped TCP-AO keys. Re-enable
        # this block once deletion of keys carrying TCP_AO_KEYF_IFINDEX is
        # fixed in the kernel.
        #
        # g1_keys = g1_keys[-1:]
        # g2_keys = g2_keys[-1:]
        # _reload_tcp_ao_config(g1, g2, 'g1-vrf-chain', g1_keys, 11)
        # _reload_tcp_ao_config(g2, g1, 'g2-vrf-chain', g2_keys, 21)
        # _assert_selected_key(self, g1, g2, 11, [11])
        # _assert_selected_key(self, g2, g1, 21, [21])


if __name__ == '__main__':
    sys.exit(unittest.main())
