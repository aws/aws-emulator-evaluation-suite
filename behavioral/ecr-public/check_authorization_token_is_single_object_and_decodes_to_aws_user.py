"""authorization-token-is-single-object-and-decodes-to-aws-user."""
from __future__ import annotations

import base64
import datetime
import re

from behavioral_harness import tags

CHECK = "authorization-token-is-single-object-and-decodes-to-aws-user"
GROUP = 'registry'
SERVICES = ['ecr-public']

# GetAuthorizationTokenResponse.authorizationData targets the AuthorizationData *structure*,
# NOT a list — private ECR's is `authorizationData: [AuthorizationData]` and each element also
# carries `proxyEndpoint`. ECR Public has neither the list nor the endpoint, because there is
# exactly one global endpoint (public.ecr.aws) and nothing to disambiguate.
_AUTH_MEMBERS = {"authorizationToken", "expiresAt"}
_BASE64_PATTERN = re.compile(r"^\S+$")  # com.amazonaws.ecrpublic#Base64


@tags("axis:happy-path", "cap:unclassified", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAuthorizationToken returns one AuthorizationData object (not private ECR's list, no
    proxyEndpoint) whose strict-base64 token decodes to AWS:<password>, expiring in the future.
    """
    ecr = ctx.client("ecr-public")

    resp = ecr.get_authorization_token()
    assert "authorizationData" in resp, f"GetAuthorizationToken must return authorizationData: {resp}"
    data = resp["authorizationData"]

    # The structural divergence from private ECR, asserted directly.
    assert isinstance(data, dict), (
        "ECR Public's authorizationData is a single AuthorizationData structure; private ECR's is "
        f"a list. Got {type(data).__name__}: {data!r}"
    )
    extra = set(data) - _AUTH_MEMBERS
    assert not extra, (
        f"AuthorizationData models only {sorted(_AUTH_MEMBERS)}; unmodeled members {sorted(extra)} "
        "leaked in (proxyEndpoint is a private-ECR-only member and must be absent)"
    )
    assert "proxyEndpoint" not in data, (
        "ECR Public has one global endpoint and models no proxyEndpoint; its presence means the "
        f"emulator reused the private-ECR response shape: {data}"
    )
    for member in sorted(_AUTH_MEMBERS):
        assert member in data, f"AuthorizationData is missing {member}: {data}"

    token = data["authorizationToken"]
    assert isinstance(token, str) and token, f"authorizationToken must be a non-empty string: {token!r}"
    assert _BASE64_PATTERN.match(token), (
        f"authorizationToken violates the Base64 shape pattern ^\\S+$ (no whitespace): {token[:32]!r}..."
    )

    # base64 with validate=True rejects any non-alphabet byte, so this is also a strict
    # "is it really base64" assertion and not merely a decode.
    raw = base64.b64decode(token, validate=True)
    decoded = raw.decode("utf-8")
    assert ":" in decoded, (
        "a decoded ECR Public authorization token is `user:password`; no ':' separator found "
        f"in {len(decoded)} decoded characters"
    )
    user, _, password = decoded.partition(":")
    assert user == "AWS", f"the decoded username must be the literal 'AWS', got {user!r}"
    assert password, "the decoded password half must be non-empty"

    expires = data["expiresAt"]
    assert isinstance(expires, datetime.datetime), (
        f"expiresAt must deserialize to a datetime, got {type(expires).__name__}: {expires!r}"
    )
    assert expires.tzinfo is not None, f"expiresAt must be timezone-aware, got {expires!r}"
    now = datetime.datetime.now(datetime.timezone.utc)
    assert expires > now, f"expiresAt must be in the future: {expires} <= {now}"
    # Documented as 12 hours. Assert a generous window rather than the exact value so a
    # legitimate change in AWS's TTL does not fail the check, while an emulator returning
    # epoch-0, `now`, or a year out still does.
    ahead = expires - now
    assert datetime.timedelta(minutes=1) < ahead < datetime.timedelta(days=2), (
        f"authorization tokens are valid for ~12 hours; expiresAt is {ahead} from now ({expires})"
    )

    # The op is repeatable and every issued token satisfies the same contract. Deliberately NOT
    # asserted: that the second token differs from the first — real AWS is free to return the
    # same still-valid token, so a freshness assertion would be a false contract.
    second = ecr.get_authorization_token()["authorizationData"]
    assert set(second) == _AUTH_MEMBERS, second
    second_raw = base64.b64decode(second["authorizationToken"], validate=True).decode("utf-8")
    assert second_raw.startswith("AWS:"), (
        f"second token does not decode to AWS:<password>, got {second_raw.partition(':')[0]!r} as user"
    )
    assert second_raw.partition(":")[2], "second token has an empty password half"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
