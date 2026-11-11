"""revoke-oauth2-token-with-iam-idempotent-on-repeat."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "revoke-oauth2-token-with-iam-idempotent-on-repeat"
GROUP = "oauth2-token"
SERVICES = ["signin"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RevokeOAuth2TokenWithIAM on the same well-formed refresh token succeeds twice, and
    IntrospectOAuth2TokenWithIAM reports it inactive with every other claim omitted before and after each
    revoke.
    """
    signin = ctx.client("signin")
    dummy_revocation_token = "ASOR" + "B" * 64
    claim_fields = (
        "clientId", "userId", "tokenType", "exp", "iat", "nbf",
        "sub", "aud", "iss", "jti", "accountId", "signinSession", "resource",
    )

    def introspect():
        return signin.introspect_oauth2_token_with_iam(
            token=dummy_revocation_token, tokenTypeHint="refresh_token"
        )

    def assert_inactive_with_no_claims(introspected, when: str) -> None:
        assert introspected["active"] is False, f"{when}: expected active=False, got {introspected!r}"
        populated = [f for f in claim_fields if introspected.get(f) is not None]
        assert not populated, f"{when}: claims must be omitted when inactive, but {populated} are populated in {introspected!r}"

    # Baseline: a never-issued token is already inactive before any revoke call,
    # so this is NOT evidence of revoke's effect -- it is the reason a state
    # assertion alone would be vacuous here.
    assert_inactive_with_no_claims(introspect(), "before first revoke")

    try:
        signin.revoke_oauth2_token_with_iam(token=dummy_revocation_token)
    except Exception as err:  # noqa: BLE001 - the assertion IS "this must not raise"
        raise AssertionError(f"first revoke of a syntactically valid unknown token must not error, got {err!r}") from err
    assert_inactive_with_no_claims(
        _poll_until(introspect, lambda r: r["active"] is False, timeout_s=20.0, interval_s=2.0),
        "after first revoke",
    )

    try:
        signin.revoke_oauth2_token_with_iam(token=dummy_revocation_token)
    except Exception as err:  # noqa: BLE001 - the assertion IS "this must not raise"
        raise AssertionError(f"second revoke of the same already-unknown token must not error, got {err!r}") from err
    assert_inactive_with_no_claims(
        _poll_until(introspect, lambda r: r["active"] is False, timeout_s=20.0, interval_s=2.0),
        "after second revoke",
    )


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last) and time.monotonic() < deadline:
        time.sleep(interval_s)
        last = probe()
    if not predicate(last):
        raise AssertionError(f"condition never satisfied within {timeout_s}s (last={last!r})")
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
