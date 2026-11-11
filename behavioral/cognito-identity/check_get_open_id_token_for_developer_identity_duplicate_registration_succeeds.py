"""get-open-id-token-for-developer-identity-duplicate-registration-succeeds."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-open-id-token-for-developer-identity-duplicate-registration-succeeds"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-registering a DeveloperUserIdentifier with its own IdentityId or none returns that
    identity; an unrelated IdentityId with the already-linked login also returns the linked identity
    and does not link the login to the other identity."""
    ci = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("sim2real-devauth-")
    pool_id = _create_pool(ctx, ci, dev_provider_name=dev_provider)
    dev_user_id = ctx.unique_name("dev-user-")

    # Create identity A registered under dev_user_id.
    resp_a = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id,
        Logins={dev_provider: dev_user_id},
        TokenDuration=900,
    )
    identity_a = resp_a["IdentityId"]
    assert resp_a["Token"], f"expected a non-empty Token for {identity_a}, got {resp_a.get('Token')!r}"

    # Registration of the dev-provider login onto identity_a is eventually
    # consistent; wait until describe_identity reflects it before relying on
    # that state for the rest of the check.
    def _identity_a_registered():
        desc = ci.describe_identity(IdentityId=identity_a)
        return dev_provider in desc.get("Logins", [])

    _poll_until(_identity_a_registered, timeout=30.0, interval=2.0)

    # Positive control: re-registering the same dev user against its OWN identity succeeds.
    resp_same = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id,
        IdentityId=identity_a,
        Logins={dev_provider: dev_user_id},
        TokenDuration=900,
    )
    assert resp_same["IdentityId"] == identity_a, (
        f"expected re-registering {dev_user_id} against its own identity {identity_a} to return "
        f"that same identity, got {resp_same['IdentityId']}"
    )

    # Create an unrelated identity B.
    identity_b = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    assert identity_b != identity_a, (
        f"expected get_id to mint a fresh identity distinct from {identity_a}, got the same id back"
    )

    # An already-registered dev user with a DIFFERENT IdentityId resolves to the identity it is
    # linked to (identity_a), ignoring the IdentityId argument. Polled briefly because the
    # login-to-identity lookup is eventually consistent.
    def _attempt():
        try:
            resp = ci.get_open_id_token_for_developer_identity(
                IdentityPoolId=pool_id,
                IdentityId=identity_b,
                Logins={dev_provider: dev_user_id},
                TokenDuration=900,
            )
            return resp["IdentityId"]
        except ClientError as exc:
            return exc.response["Error"]["Code"]

    resolved_identity = _poll_until(
        _attempt,
        predicate=lambda i: i == identity_a,
        timeout=30.0,
        interval=3.0,
    )
    assert resolved_identity == identity_a, resolved_identity

    # Identity B was not mutated by that call: it still has no dev-provider login.
    desc_b = ci.describe_identity(IdentityId=identity_b)
    logins_b = desc_b.get("Logins", [])
    assert dev_provider not in logins_b, (
        f"expected identity_b {identity_b} to remain unlinked from {dev_provider} after the "
        f"mismatched-IdentityId call resolved to {identity_a} instead, got Logins={logins_b}"
    )


def _poll_until(fn, predicate=None, timeout: float = 30.0, interval: float = 2.0):
    """Call fn() repeatedly until predicate(result) is true (or, with no
    predicate, until fn() itself returns a truthy value), bounded by timeout."""
    deadline = time.monotonic() + timeout
    result = fn()
    check = predicate if predicate is not None else (lambda r: bool(r))
    while not check(result):
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval)
        result = fn()
    return result


def _create_pool(ctx, ci, *, unauth: bool = True, dev_provider_name: str | None = None) -> str:

    kwargs = {
        "IdentityPoolName": ctx.unique_name("sim2real-behav-pool-"),
        "AllowUnauthenticatedIdentities": unauth,
        "IdentityPoolTags": {"sim2real": CHECK},
    }
    if dev_provider_name:
        kwargs["DeveloperProviderName"] = dev_provider_name
    pool_id = ci.create_identity_pool(**kwargs)["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
