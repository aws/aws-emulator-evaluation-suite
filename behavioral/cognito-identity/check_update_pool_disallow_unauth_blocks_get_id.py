"""update-pool-disallow-unauth-blocks-get-id."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-pool-disallow-unauth-blocks-get-id"
GROUP = 'pool-config'
SERVICES = ['cognito-identity']

def _refusal(fn, what):
    """Call fn(); return (Code, Message) when it is refused, and raise when it succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"{what} must be refused, but the call succeeded")

def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    kwargs.setdefault("IdentityPoolTags", {"sim2real": CHECK})
    pool_id = client.create_identity_pool(
        IdentityPoolName=name, AllowUnauthenticatedIdentities=allow_unauth, **kwargs
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id

def _list_identities(client, pool_id):
    """Every identity in the pool, paginated — used as a set-difference to prove absence."""
    ids = set()
    next_token = None
    pages = 0
    while True:
        kwargs = {"IdentityPoolId": pool_id, "MaxResults": 60}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = client.list_identities(**kwargs)
        ids.update(i["IdentityId"] for i in resp.get("Identities", []))
        next_token = resp.get("NextToken")
        pages += 1
        if not next_token or pages > 50:
            return ids

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Flipping AllowUnauthenticatedIdentities True->False immediately blocks anonymous GetId,
    allocates nothing for the blocked call, and flipping it back to True lets the identical call
    succeed again."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True)
    name = ev.describe_identity_pool(IdentityPoolId=pool_id)["IdentityPoolName"]
    first_id = ev.get_id(IdentityPoolId=pool_id)["IdentityId"]
    assert first_id, "positive control: GetId must succeed while unauthenticated identities are allowed"

    ids_before_block = _list_identities(ev, pool_id)

    ev.update_identity_pool(
        IdentityPoolId=pool_id,
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=False,
    )
    assert (
        ev.describe_identity_pool(IdentityPoolId=pool_id)["AllowUnauthenticatedIdentities"]
        is False
    ), "UpdateIdentityPool must be reflected by an independent DescribeIdentityPool read"
    code, message = _refusal(
        lambda: ev.get_id(IdentityPoolId=pool_id),
        "anonymous GetId once unauthenticated identities are disabled",
    )
    assert code == "NotAuthorizedException", (
        f"anonymous GetId must be rejected once unauthenticated identities are disabled, got "
        f"{code!r}: {message!r}"
    )
    expected_message = "Unauthenticated access is not supported for this identity pool."
    assert message == expected_message, (
        f"expected the message {expected_message!r} for anonymous GetId on a pool that disallows "
        f"unauthenticated identities, got {message!r}"
    )

    ids_after_block = _list_identities(ev, pool_id)
    assert ids_after_block == ids_before_block, (
        f"a rejected GetId must allocate no identity, pool gained "
        f"{sorted(ids_after_block - ids_before_block)!r}"
    )

    assert ev.describe_identity(IdentityId=first_id)["IdentityId"] == first_id, (
        "the identity created before the block must remain independently readable"
    )

    # restore: flip the flag back and demand the identical call now succeeds again
    ev.update_identity_pool(
        IdentityPoolId=pool_id,
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=True,
    )
    restored_id = ev.get_id(IdentityPoolId=pool_id)["IdentityId"]
    assert restored_id, (
        "restore: GetId must succeed again once unauthenticated identities are re-enabled"
    )
    ctx.on_cleanup(lambda: ev.delete_identities(IdentityIdsToDelete=[restored_id]))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
