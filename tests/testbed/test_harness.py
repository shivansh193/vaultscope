"""Peer harness (P1-T1). Needs Docker, so every test here is slow."""

import pytest

from testbed import harness
from testbed.config_generator import generate_configs

pytestmark = pytest.mark.slow


def _gcm_config():
    return next(c for c in generate_configs() if c.name.startswith("tunnel_aes256gcm"))


@pytest.fixture(scope="module")
def image():
    harness.build_image()


def test_strongswan_config_syntax_valid(image):
    """The spec's mandatory P1-T1 test: generated configs load into swanctl."""
    with harness.peer_pair(_gcm_config(), index=90) as pair:
        result = pair.exec(pair.initiator, "swanctl", "--load-all")
        assert result.returncode == 0
        assert "loaded connection 'vaultscope'" in result.stdout


def test_pair_establishes_a_real_sa(image):
    with harness.peer_pair(_gcm_config(), index=91) as pair:
        pair.establish()
        sas = pair.exec(pair.initiator, "swanctl", "--list-sas").stdout
        assert "ESTABLISHED" in sas
        assert "INSTALLED" in sas


def test_a_config_that_cannot_establish_raises_rather_than_hanging(image):
    """A cell that will not come up must fail fast, not stall a 300-cell run."""
    with harness.peer_pair(_gcm_config(), index=92) as pair:
        pair.exec(pair.responder, "pkill", "-f", "charon", check=False)
        with pytest.raises(harness.HarnessError):
            pair.establish(timeout=8)
