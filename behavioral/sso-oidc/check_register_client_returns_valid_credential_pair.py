"""register-client-returns-valid-credential-pair."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-client-returns-valid-credential-pair"
GROUP = "representation"
SERVICES = ["sso-oidc"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterClient returns a non-empty clientId and clientSecret, a clientIdIssuedAt within 5 s of the
    call and a clientSecretExpiresAt 1 day to 1 year later, and the pair reaches CreateToken's grant
    lookup (InvalidGrantException "Invalid device code provided"), not client authentication."""
    sso_oidc = ctx.client("sso-oidc")
    before = time.time()
    resp = sso_oidc.register_client(
        clientName=ctx.unique_name("sim2real-ssooidc-client-"),
        clientType="public",
    )
    after = time.time()

    assert resp["clientId"], "clientId must be non-empty"
    assert resp["clientSecret"], "clientSecret must be non-empty"

    issued_at = resp["clientIdIssuedAt"]
    expires_at = resp["clientSecretExpiresAt"]
    assert before - 5 <= issued_at <= after + 5, (
        f"clientIdIssuedAt {issued_at} must be the live issuance clock, "
        f"expected within [{before - 5}, {after + 5}]"
    )
    ttl = expires_at - issued_at
    assert 86400 <= ttl <= 31536000, (
        f"clientSecretExpiresAt must be a multi-day-to-annual validity "
        f"window after clientIdIssuedAt, got ttl={ttl}s"
    )

    try:
        sso_oidc.create_token(
            clientId=resp["clientId"],
            clientSecret=resp["clientSecret"],
            grantType="urn:ietf:params:oauth:grant-type:device_code",
            deviceCode="sim2real-fabricated-device-code-does-not-exist",
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "InvalidGrantException", (
            f"a real credential pair should authenticate and reach "
            f"grant-lookup (InvalidGrantException for the unknown code), "
            f"got {code!r}"
        )
        message = err.response["Error"]["Message"]
        assert message == "Invalid device code provided", (
            f"unexpected message: {message!r}"
        )
    else:
        raise AssertionError(
            "expected InvalidGrantException for a fabricated device code"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
