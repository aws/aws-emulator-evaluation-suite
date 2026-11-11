"""get-open-id-token-for-developer-identity-idempotent-same-user."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-open-id-token-for-developer-identity-idempotent-same-user"
GROUP = "identity-lifecycle"
SERVICES = ["cognito-identity"]


def _list_identity_ids(ci, pool_id):
    """Every identity id in the pool, paginated (ListIdentities caps MaxResults at 60)."""
    ids = set()
    next_token = None
    while True:
        kwargs = {"IdentityPoolId": pool_id, "MaxResults": 60}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = ci.list_identities(**kwargs)
        ids.update(i["IdentityId"] for i in resp.get("Identities", []))
        next_token = resp.get("NextToken")
        if not next_token:
            return ids


def _wait_for_identity(ci, pool_id, identity_id, timeout_s=60.0, interval_s=3.0):
    """The pool's identity set once it shows the identity — ListIdentities is eventually
    consistent right after a create, so the independent read below needs a bounded retry, not a
    single call."""
    deadline = time.time() + timeout_s
    last: set[str] = set()
    while time.time() < deadline:
        last = _list_identity_ids(ci, pool_id)
        if identity_id in last:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"ListIdentities never showed {identity_id!r} within {timeout_s}s; last saw {sorted(last)!r}"
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Calling GetOpenIdTokenForDeveloperIdentity twice for the same developer user resolves to the
    SAME IdentityId, and the pool ends up holding exactly that one identity — not a phantom id that
    comparing the two calls' own responses alone would miss."""
    ci = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("sim2real-dev-")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-"),
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=dev_provider,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    dev_user = ctx.unique_name("user-")
    first = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dev_user}
    )
    identity_id = first["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))

    second = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dev_user}
    )
    assert second["IdentityId"] == identity_id, (
        f"re-authenticating the same developer user produced a new identity: "
        f"{identity_id!r} != {second['IdentityId']!r}"
    )
    # Tokens are per-call but both must still validate against the same identity/pool pair.
    assert first["Token"] != "" and second["Token"] != "", (
        "expected non-empty tokens from both calls"
    )

    # Independent read at the destination: a target that mints a fresh identity per call but
    # echoes back a fixed IdentityId would still pass the comparison above. ListIdentities is the
    # side channel that shows what the pool actually holds.
    seen = _wait_for_identity(ci, pool_id, identity_id)
    assert seen == {identity_id}, (
        f"two calls for the same developer user should leave the pool with exactly the one "
        f"identity {identity_id!r}, found {sorted(seen)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
