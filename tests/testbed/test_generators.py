"""Traffic generators (P1-T2)."""

import re

import pytest

from testbed.generators.run import GENERATORS, TRAFFIC_CLASSES, run_traffic


def test_every_class_in_the_spec_has_a_generator():
    assert set(GENERATORS) == set(TRAFFIC_CLASSES)
    assert len(TRAFFIC_CLASSES) == 6


def test_chat_is_declared_a_substitution_and_nothing_else_is():
    substitutions = {name for name, g in GENERATORS.items() if g.substitution}
    assert substitutions == {"Chat"}
    assert "substitut" in GENERATORS["Chat"].description.lower()


def test_client_argv_templates_take_peer_and_duration():
    for name, generator in GENERATORS.items():
        joined = " ".join(generator.client)
        addresses_peer = "{peer}" in joined or "{peer_url}" in joined
        assert addresses_peer, f"{name} never addresses the peer"
        assert "{duration}" in joined, f"{name} never bounds its runtime"


def test_url_generators_bracket_ipv6_literals():
    """An IPv6 literal in a URL needs brackets. Without them ffmpeg and curl
    silently emit nothing, and every IPv6 Video and Web cell captures noise."""
    from testbed.generators.run import _fill

    for name in ("Video", "Web"):
        filled = " ".join(_fill(GENERATORS[name].client, "fd00:90:12::3", 30))
        assert "[fd00:90:12::3]" in filled, f"{name} did not bracket the IPv6 peer"
        assert "//fd00:" not in filled, f"{name} left a bare IPv6 literal in a URL"


def test_non_url_generators_do_not_bracket():
    """ping and sipp take a bare address; brackets would break them."""
    from testbed.generators.run import _fill

    for name in ("ICMP", "VoIP"):
        filled = " ".join(_fill(GENERATORS[name].client, "fd00:90:12::3", 30))
        assert "[fd00:90:12::3]" not in filled, f"{name} must take a bare address"


@pytest.mark.slow
def test_traffic_actually_crosses_the_tunnel():
    from testbed import harness
    from testbed.config_generator import generate_configs

    harness.build_image()
    config = next(c for c in generate_configs() if c.name.startswith("tunnel_aes256gcm"))
    with harness.peer_pair(config, index=93) as pair:
        pair.establish()

        def bytes_out() -> int:
            """Bytes the SA has actually protected, from swanctl's own counter."""
            text = pair.exec(pair.initiator, "swanctl", "--list-sas", "--raw").stdout
            match = re.search(r"bytes-out=(\d+)", text)
            return int(match.group(1)) if match else 0

        before = bytes_out()
        run_traffic(pair, "ICMP", duration=5)
        assert bytes_out() > before, "no traffic crossed the SA"
