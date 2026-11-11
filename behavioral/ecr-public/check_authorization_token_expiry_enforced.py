"""authorization-token-expiry-enforced."""
from __future__ import annotations

import base64
import datetime as dt

from behavioral_harness import tags

CHECK = "authorization-token-expiry-enforced"
GROUP = "visibility-timeout-ttl"
SERVICES = ["ecr-public"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAuthorizationToken's expiresAt is ~12h after issuance on each call, the token decodes to
    AWS:<password>, and a later token never expires before an earlier one.

    Reference: https://docs.aws.amazon.com/AmazonECRPublic/latest/APIReference/API_GetAuthorizationToken.html
    """
    ecrp = _regional_client(ctx, "ecr-public")

    before1 = dt.datetime.now(dt.timezone.utc)
    data1 = ecrp.get_authorization_token()["authorizationData"]
    after1 = dt.datetime.now(dt.timezone.utc)
    token1 = data1["authorizationToken"]
    expires1 = data1["expiresAt"]

    ttl1_low = (expires1 - after1).total_seconds()
    ttl1_high = (expires1 - before1).total_seconds()
    assert 11.5 * 3600 <= ttl1_low and ttl1_high <= 12.5 * 3600, (
        f"expiresAt is not within the documented ~12h TTL window: "
        f"ttl_low={ttl1_low}s ttl_high={ttl1_high}s"
    )

    decoded1 = base64.b64decode(token1).decode()
    user1, sep, password1 = decoded1.partition(":")
    assert sep == ":" and user1 == "AWS" and len(password1) > 0, (
        f"decoded token is not the documented 'AWS:<password>' form: {decoded1[:20]!r}..."
    )

    before2 = dt.datetime.now(dt.timezone.utc)
    data2 = ecrp.get_authorization_token()["authorizationData"]
    after2 = dt.datetime.now(dt.timezone.utc)
    expires2 = data2["expiresAt"]

    # AWS may return the same still-valid token for near-simultaneous calls, so the expiry
    # need not strictly advance.
    assert expires2 >= expires1, (
        f"second token's expiresAt did not advance past the first: {expires2} < {expires1}"
    )
    ttl2_low = (expires2 - after2).total_seconds()
    ttl2_high = (expires2 - before2).total_seconds()
    assert 11.5 * 3600 <= ttl2_low and ttl2_high <= 12.5 * 3600, (
        f"second token's expiresAt is not within the documented ~12h TTL window: "
        f"ttl_low={ttl2_low}s ttl_high={ttl2_high}s"
    )


def _regional_client(ctx, service: str, region: str = "us-east-1"):
    """ECR Public is a us-east-1-only API, so the client is pinned through
    `ctx.client(..., region=)`."""
    return ctx.client(service, region=region)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
