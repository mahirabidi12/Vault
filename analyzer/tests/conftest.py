import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


import pytest  # noqa: E402


@pytest.fixture
def cloud(monkeypatch):
    """Fake AWS account (moto) with the PkgGuard table, bucket and state machine."""
    from moto import mock_aws

    from cloud_helpers import REGION, make_fake_cloud

    for key, value in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing", "AWS_DEFAULT_REGION": REGION}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    with mock_aws():
        yield make_fake_cloud()
