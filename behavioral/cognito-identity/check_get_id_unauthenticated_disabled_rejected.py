"""get-id-unauthenticated-disabled-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-id-unauthenticated-disabled-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _list_identities(ci, pool_id):
    ids = set()
    next_token = None
    for _ in range(50):
        kwargs = {"IdentityPoolId": pool_id, "MaxResults": 60}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = ci.list_identities(**kwargs)
        ids.update(i["IdentityId"] for i in resp.get("Identities", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return ids


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With AllowUnauthenticatedIdentities=False, a Logins-less GetId is refused with
    NotAuthorizedException and the exact message and allocates no identity; restoring the flag makes
    the identical call issue a new identity."""
    ci = ctx.client("cognito-identity")
    name = ctx.unique_name("sim2real_pool_").replace("-", "_")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=name, AllowUnauthenticatedIdentities=True
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    # ---- positive control: the pool and the call shape work before we break anything
    control_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[control_id]))
    ids_before_break = _list_identities(ci, pool_id)
    assert control_id in ids_before_break, (
        f"positive control GetId {control_id!r} did not appear in ListIdentities before the flag "
        f"was disabled"
    )

    # ---- break exactly one thing
    ci.update_identity_pool(
        IdentityPoolId=pool_id, IdentityPoolName=name, AllowUnauthenticatedIdentities=False
    )
    disabled = ci.describe_identity_pool(IdentityPoolId=pool_id)["AllowUnauthenticatedIdentities"]
    assert disabled is False, f"expected AllowUnauthenticatedIdentities=False after update, got {disabled!r}"

    err = _client_error(lambda: ci.get_id(IdentityPoolId=pool_id))
    code, message = err.get("Code"), err.get("Message") or ""
    assert code == "NotAuthorizedException", f"expected NotAuthorizedException, got {code!r}: {message!r}"
    expected = "Unauthenticated access is not supported for this identity pool."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # ---- effect absent: nothing new was allocated for the refused call
    ids_after_reject = _list_identities(ci, pool_id)
    assert ids_after_reject == ids_before_break, (
        f"an identity appeared for a rejected GetId: {sorted(ids_after_reject - ids_before_break)!r}"
    )

    # ---- restore: flip the flag back and demand the identical call now succeeds
    ci.update_identity_pool(
        IdentityPoolId=pool_id, IdentityPoolName=name, AllowUnauthenticatedIdentities=True
    )
    restored_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[restored_id]))
    assert restored_id not in ids_before_break, (
        f"GetId after re-enabling unauthenticated identities returned the pre-existing identity "
        f"{restored_id!r} instead of allocating a new one"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
