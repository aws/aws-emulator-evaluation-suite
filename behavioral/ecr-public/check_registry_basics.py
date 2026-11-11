"""registry-basics."""
from __future__ import annotations

import base64
import re
from datetime import datetime, timezone

from behavioral_harness import tags


CHECK = "registry-basics"
GROUP = 'registry'
SERVICES = ['ecr-public']

_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeRegistries lists exactly the caller's registry and GetAuthorizationToken returns an unexpired AWS:<password> token."""
    # ecr-public's control-plane API is served only from us-east-1; on real AWS ctx.region
    # defaults elsewhere and every call below would fail with UnsupportedCommandException.
    ecr = ctx.client("ecr-public", region="us-east-1")

    registries = ecr.describe_registries()["registries"]
    assert registries, f"describe_registries returned no registries: {registries}"
    for r in registries:
        assert _ACCOUNT_RE.match(r.get("registryId", "")), f"registryId not a 12-digit account id: {r}"
    assert [r["registryId"] for r in registries] == [ctx.account], (
        f"expected exactly the caller's registry {ctx.account!r}, got {[r.get('registryId') for r in registries]!r}"
    )

    auth = ecr.get_authorization_token()
    token_data = auth["authorizationData"]
    token = token_data.get("authorizationToken")
    assert token, token_data
    decoded = base64.b64decode(token).decode("utf-8")
    assert decoded.startswith("AWS:") and len(decoded) > len("AWS:"), (
        f"decoded token must be 'AWS:<password>' with a non-empty password, got {decoded!r}"
    )

    expires_at = token_data.get("expiresAt")
    assert expires_at is not None, token_data
    expires_dt = (
        datetime.fromtimestamp(expires_at, tz=timezone.utc)
        if isinstance(expires_at, (int, float))
        else expires_at
    )
    now = datetime.now(timezone.utc)
    assert expires_dt > now, f"expiresAt {expires_dt} is not in the future (now={now})"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
