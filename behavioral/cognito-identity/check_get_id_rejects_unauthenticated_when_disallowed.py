"""get-id-rejects-unauthenticated-when-disallowed."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-id-rejects-unauthenticated-when-disallowed"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


def _refusal(fn):
    """Call fn(); return the refusal's (Code, Message). An unexpected success raises, so an
    over-permissive target never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected GetId to be refused, but it SUCCEEDED and returned {result!r}")


def _list_identities(client, pool_id):
    """Every identity in the pool, paginated -- the effect-absence assertion below is a set diff."""
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Anonymous GetId on a pool with AllowUnauthenticatedIdentities=False is refused with
    NotAuthorizedException and the exact message and adds no identity; once the pool allows it, the
    identical call issues a new identity that ListIdentities shows."""
    ci = ctx.client("cognito-identity")
    name = f"sim2real-behav-noguest-{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = ci.create_identity_pool(IdentityPoolName=name, AllowUnauthenticatedIdentities=False)[
        "IdentityPoolId"
    ]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    ids_before = _list_identities(ci, pool_id)

    code, message = _refusal(lambda: ci.get_id(IdentityPoolId=pool_id))
    assert code == "NotAuthorizedException", (
        f"pool disallows unauthenticated identities; expected NotAuthorizedException for "
        f"anonymous GetId, got {code!r}: {message!r}"
    )
    assert message == "Unauthenticated access is not supported for this identity pool.", message

    ids_after_reject = _list_identities(ci, pool_id)
    assert ids_after_reject == ids_before, (
        f"an identity appeared for a rejected GetId: {sorted(ids_after_reject - ids_before)!r}"
    )

    # restore: flipping the flag makes the identical call succeed. This is the positive control
    # that a single always-reject assertion cannot provide.
    ci.update_identity_pool(
        IdentityPoolId=pool_id, IdentityPoolName=name, AllowUnauthenticatedIdentities=True
    )
    restored_identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[restored_identity_id]))
    assert restored_identity_id not in ids_before, (
        f"GetId after enabling unauthenticated identities returned a pre-existing identity "
        f"{restored_identity_id!r} instead of allocating one"
    )

    # terminal read: independent of the mutating GetId call above, at the destination.
    ids_after_restore = _list_identities(ci, pool_id)
    assert restored_identity_id in ids_after_restore, (
        f"the identity {restored_identity_id!r} allocated once unauthenticated access was "
        f"enabled does not appear in the pool's own identity listing: {sorted(ids_after_restore)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
