#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2025, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
When a static route configured as backup (based-on the admin-distance) to an
EBGP route is redistributed to BGP, make sure the EBGP route is always favored
regardless whether the static route or the EBGP route is received first.

Case 1: static route first, and then EBGP route.
Case 2: EBGP route first, and then static route.
"""

import os
import sys
import time
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_redistribute_ebgp():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _bgp_check_neighbor(router, neighbor):
        output = json.loads(
            router.vtysh_cmd("show bgp neighbor {} json".format(neighbor))
        )
        expected = {
            neighbor:{
                "bgpState": "Established",
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_check_route_sourced(router, prefix):
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
        )
        expected = {"paths": [{"valid": True, "sourced": True}]}
        return topotest.json_cmp(output, expected)

    def _bgp_check_route_bestpath(router, prefix, neighbor):
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
        )
        expected = {
            "paths":[
                {
                    "bestpath":{
                        "overall":True,
                    },
                    "peer":{
                        "peerId":neighbor,
                    }
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    def _check_ip_route_selected(router, prefix):
        output = json.loads(
            router.vtysh_cmd("show ip route {} json".format(prefix))
        )
        expected = {
            prefix:[
                {
                    "prefix": prefix,
                    "protocol": "bgp",
                    "selected": True,
                    "distance": 20,
                },
                {
                    "prefix": prefix,
                    "protocol": "static",
                    "distance": 30,
                }
            ]
        }
        return topotest.json_cmp(output, expected)


    step("r1: configure the backup static route")
    r1.vtysh_cmd(
        """
    configure terminal
        ip route 10.0.50.0/24 Null0 30
    """
    )

    step("r1: check if the static route is redistributed to bgp")
    test_func = functools.partial(_bgp_check_route_sourced, r1, "10.0.50.0/24")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "static route 10.0.50.0/24 not redistributed in bgp"

    step("r1: check BGP session is established with r2")
    test_func = functools.partial(_bgp_check_neighbor, r1, "192.168.12.2")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "BGP neighbor 192.168.12.2 not established"

    step("r2: config the static route")
    r2.vtysh_cmd(
        """
    configure terminal
        ip route 10.0.50.0/24 Null0
    """
    )

    step("r1: verify the ebgp route is favored in BGP")
    test_func = functools.partial(_bgp_check_route_bestpath, r1, "10.0.50.0/24", "192.168.12.2")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Static route first and then EBGP, but EBGP route not favored in BGP"

    step("r1: verify the ebgp route is favored in RIB")
    test_func = functools.partial(_check_ip_route_selected, r1, "10.0.50.0/24")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "static route first and then EBGP, but EBGP route not favored in RIB"

    step("r1: delete, and then add the backup static route")
    r1.vtysh_cmd(
        """
    configure terminal
        no ip route 10.0.50.0/24 Null0 30
    """
    )

    r1.vtysh_cmd(
        """
    configure terminal
        ip route 10.0.50.0/24 Null0 30
    """
    )

    step("r1: verify the ebgp route is still favored")
    test_func = functools.partial(_check_ip_route_selected, r1, "10.0.50.0/24")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "EBGP first and then static route, but EBGP route not favored"


def test_bgp_bestpath_admin_distance_ignore():
    """
    Verify 'bgp bestpath admin-distance ignore' skips step-0 admin-distance
    comparison so a locally redistributed route (higher weight) beats an
    eBGP path with a lower admin distance, and toggling the knob off
    recalculates bestpaths immediately.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _bgp_check_local_only(router, prefix):
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
        )
        paths = output.get("paths", [])
        if len(paths) != 1:
            return "expected 1 path, got {}".format(len(paths))
        expected = {"paths": [{"valid": True, "sourced": True}]}
        return topotest.json_cmp(output, expected)

    def _bgp_check_local_wins_by_weight(router, prefix, neighbor):
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
        )
        expected = {
            "paths": [
                {
                    "valid": True,
                    "sourced": True,
                    "weight": 32768,
                    "bestpath": {
                        "overall": True,
                        "selectionReason": "Weight",
                    },
                },
                {
                    "valid": True,
                    "peer": {
                        "peerId": neighbor,
                    },
                },
            ]
        }
        return topotest.json_cmp(output, expected)

    def _check_static_selected(router, prefix):
        output = json.loads(
            router.vtysh_cmd("show ip route {} json".format(prefix))
        )
        expected = {
            prefix: [
                {
                    "prefix": prefix,
                    "protocol": "static",
                    "selected": True,
                    "distance": 30,
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    def _bgp_check_ebgp_wins(router, prefix, neighbor):
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
        )
        expected = {
            "paths": [
                {
                    "bestpath": {
                        "overall": True,
                    },
                    "peer": {
                        "peerId": neighbor,
                    },
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    def _check_bgp_selected(router, prefix):
        output = json.loads(
            router.vtysh_cmd("show ip route {} json".format(prefix))
        )
        expected = {
            prefix: [
                {
                    "prefix": prefix,
                    "protocol": "bgp",
                    "selected": True,
                    "distance": 20,
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    step("r2: withdraw 10.0.50.0/24 so r1 redistributes its local static route")
    r2.vtysh_cmd(
        """
    configure terminal
        no ip route 10.0.50.0/24 Null0
    """
    )

    test_func = functools.partial(_bgp_check_local_only, r1, "10.0.50.0/24")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1 did not converge back to local redistributed path"

    step("r1: enable bgp bestpath admin-distance ignore")
    r1.vtysh_cmd(
        """
    configure terminal
        router bgp 65001
            bgp bestpath admin-distance ignore
    """
    )
    assert "bgp bestpath admin-distance ignore" in r1.vtysh_cmd("show running-config")

    step("r2: re-advertise 10.0.50.0/24 via eBGP")
    r2.vtysh_cmd(
        """
    configure terminal
        ip route 10.0.50.0/24 Null0
    """
    )

    step("r1: verify local redistributed path beats eBGP path by weight")
    test_func = functools.partial(
        _bgp_check_local_wins_by_weight, r1, "10.0.50.0/24", "192.168.12.2"
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "local redistributed route did not win by weight: {}".format(
        result
    )

    test_func = functools.partial(_check_static_selected, r1, "10.0.50.0/24")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "static route did not remain selected in RIB"

    step("r1: disable bgp bestpath admin-distance ignore and verify recalculation")
    r1.vtysh_cmd(
        """
    configure terminal
        router bgp 65001
            no bgp bestpath admin-distance ignore
    """
    )
    assert "bgp bestpath admin-distance ignore" not in r1.vtysh_cmd(
        "show running-config"
    )

    test_func = functools.partial(
        _bgp_check_ebgp_wins, r1, "10.0.50.0/24", "192.168.12.2"
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "eBGP path did not win after disabling admin-distance ignore"

    test_func = functools.partial(_check_bgp_selected, r1, "10.0.50.0/24")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "BGP route not selected in RIB after disabling knob"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
