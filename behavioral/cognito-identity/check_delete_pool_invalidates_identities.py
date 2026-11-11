"""delete-pool-invalidates-identities."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-pool-invalidates-identities"
GROUP = 'lifecycle'
SERVICES = ['cognito-identity']

def _error(fn):
    """Call fn(); return the ClientError's (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register a DeleteIdentityPool cleanup that tolerates the check deleting it."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real": CHECK},
        **kwargs,
    )["IdentityPoolId"]

    def _cleanup():
        try:
            client.delete_identity_pool(IdentityPoolId=pool_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return pool_id

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting an identity pool makes previously-issued identities unresolvable."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True)
    identity_id = ev.get_id(IdentityPoolId=pool_id)["IdentityId"]
    desc = ev.describe_identity(IdentityId=identity_id)
    assert desc["IdentityId"] == identity_id, (
        f"expected describe_identity to echo {identity_id!r} before deletion, got {desc.get('IdentityId')!r}"
    )
    ev.delete_identity_pool(IdentityPoolId=pool_id)
    # The identity's lookup fails on its pool: the message names the deleted pool, not the identity.
    not_found = ("ResourceNotFoundException", f"IdentityPool '{pool_id}' not found.")
    err = _error(lambda: ev.describe_identity(IdentityId=identity_id))
    assert err == not_found, f"expected {not_found}, got {err}"
    err2 = _error(lambda: ev.get_id(IdentityPoolId=pool_id))
    assert err2 == not_found, f"expected {not_found}, got {err2}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
