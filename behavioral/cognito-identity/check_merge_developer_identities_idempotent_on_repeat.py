"""merge-developer-identities-idempotent-on-repeat."""
from __future__ import annotations

import time
import uuid
from typing import Any

from behavioral_harness import tags

CHECK = "merge-developer-identities-idempotent-on-repeat"
GROUP = "state-machine"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Calling MergeDeveloperIdentities twice with the same identifiers doesn't duplicate logins or error."""
    client = ctx.client("cognito-identity")
    dev_provider = f"login.{ctx.unique_name('sim2real')}"
    pool_id = _create_pool(ctx, client, DeveloperProviderName=dev_provider)

    source_user = f"source-{uuid.uuid4()}"
    dest_user = f"dest-{uuid.uuid4()}"

    source_identity = client.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: source_user}
    )["IdentityId"]
    dest_identity = client.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dest_user}
    )["IdentityId"]
    assert source_identity != dest_identity, "source and destination should start as distinct identities"

    merge1 = client.merge_developer_identities(
        SourceUserIdentifier=source_user,
        DestinationUserIdentifier=dest_user,
        DeveloperProviderName=dev_provider,
        IdentityPoolId=pool_id,
    )
    # Real AWS does not guarantee the "destination" identifier's IdentityId survives the merge —
    # only that the two pre-merge identities collapse into exactly one of them. Capture whichever
    # one it actually is and hold the check to *that* being stable/consistent, rather than assuming
    # the destination side wins.
    merged_identity = merge1["IdentityId"]
    assert merged_identity in (source_identity, dest_identity), (
        f"merge should resolve to one of the two pre-merge identities, got {merged_identity}"
    )

    # MaxResults bounds how many DeveloperUserIdentifierList entries a single call returns;
    # since we expect both the source and destination identifiers to be present after the
    # merge, it must be large enough to hold both (1 would silently truncate to a single entry
    # and never converge, even though the merge succeeded).
    #
    # Querying LookupDeveloperIdentity by DeveloperUserIdentifier only resolves that one
    # identifier to its IdentityId -- real AWS echoes back just the identifier you supplied in
    # DeveloperUserIdentifierList, not the full set linked to the identity. To observe the
    # merged set (both source and destination identifiers now pointing at the same identity),
    # you must look up by IdentityId instead.
    lookup1 = _poll_until(
        lambda: client.lookup_developer_identity(
            IdentityPoolId=pool_id, IdentityId=merged_identity, MaxResults=15
        ),
        lambda resp: sorted(resp.get("DeveloperUserIdentifierList", []))
        == sorted([source_user, dest_user]),
    )
    assert lookup1["IdentityId"] == merged_identity, (
        f"lookup by merged IdentityId returned {lookup1['IdentityId']}, expected {merged_identity}"
    )
    assert sorted(lookup1["DeveloperUserIdentifierList"]) == sorted([source_user, dest_user]), (
        f"expected exactly [source, dest] linked after merge, got {lookup1['DeveloperUserIdentifierList']}"
    )

    # repeat the merge with the same source/destination identifiers
    merge2 = client.merge_developer_identities(
        SourceUserIdentifier=source_user,
        DestinationUserIdentifier=dest_user,
        DeveloperProviderName=dev_provider,
        IdentityPoolId=pool_id,
    )
    assert merge2["IdentityId"] == merged_identity, "repeat merge changed the resolved identity"

    # As above, look up by IdentityId (not DeveloperUserIdentifier) to see the full merged set.
    lookup2 = _poll_until(
        lambda: client.lookup_developer_identity(
            IdentityPoolId=pool_id, IdentityId=merged_identity, MaxResults=15
        ),
        lambda resp: sorted(resp.get("DeveloperUserIdentifierList", []))
        == sorted([source_user, dest_user]),
    )
    assert lookup2["IdentityId"] == merged_identity, (
        f"repeat lookup by merged IdentityId returned {lookup2['IdentityId']}, expected {merged_identity}"
    )
    assert sorted(lookup2["DeveloperUserIdentifierList"]) == sorted([source_user, dest_user]), (
        f"repeat merge duplicated developer user identifiers: {lookup2['DeveloperUserIdentifierList']}"
    )


def _poll_until(fn, predicate, timeout: float = 30.0, interval: float = 2.0):
    """Call fn() repeatedly until predicate(result) is True, else raise on timeout.

    Cognito's developer-identity mapping updates (e.g. after MergeDeveloperIdentities) are not
    guaranteed to be immediately consistent; bound the wait rather than assuming instant effect.
    """
    deadline = time.monotonic() + timeout
    result = fn()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout}s (last={result!r})")
        time.sleep(interval)
        result = fn()
    return result


def _create_pool(ctx, client, **extra_fields: Any) -> str:
    params = {
        "IdentityPoolName": ctx.unique_name("sim2real-idp-"),
        "AllowUnauthenticatedIdentities": True,
    }
    params.update(extra_fields)
    pool_id = client.create_identity_pool(**params)["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
