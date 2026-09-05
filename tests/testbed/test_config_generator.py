"""Stage 0 config generator (P1-T1)."""

import re

from testbed.config_generator import generate_configs, render_swanctl


def test_all_cipher_configs_generated():
    configs = generate_configs()
    assert len(configs) >= 96  # 2 x 6 x 3 x 2 x 2 minimum without traffic-type dim


def test_config_naming_convention():
    configs = generate_configs()
    for c in configs:
        assert re.match(r"^(tunnel|transport)_.+_.+_(pfs|nopfs)_(ipv4|ipv6)$", c.name)


def test_every_matrix_dimension_is_covered():
    configs = generate_configs()
    assert {c.mode for c in configs} == {"tunnel", "transport"}
    assert {c.ip_version for c in configs} == {"IPv4", "IPv6"}
    assert {c.pfs for c in configs} == {True, False}
    assert len({c.suite.slug for c in configs}) == 6
    assert len({c.dh_slug for c in configs}) == 3


def test_weak_suites_are_present_because_they_are_the_point():
    configs = generate_configs()
    slugs = {c.suite.slug for c in configs}
    assert "descbc_md5" in slugs
    assert "3descbc_sha1" in slugs
    assert "modp1024" in {c.dh_slug for c in configs}


def test_label_config_speaks_the_canonical_models_vocabulary():
    from core.models import IkeParams

    config = next(c for c in generate_configs() if c.suite.slug == "aes256gcm")
    label = config.label_config()
    assert label["encryption"] == "AES-256-GCM"
    assert label["integrity"] == "implicit"
    # Every value must be assignable to the canonical model without translation.
    IkeParams(**{k: v for k, v in label.items() if k in IkeParams.model_fields})


def test_render_swanctl_is_loadable_shaped():
    config = generate_configs()[0]
    text = render_swanctl(config, "10.90.0.2", "10.90.0.3", "alice", "bob")
    assert "connections {" in text
    assert "local-1 {" in text and "remote-1 {" in text
    assert "secrets {" in text
    assert ";" not in text.replace("\n", "")  # swanctl.conf is newline-structured
