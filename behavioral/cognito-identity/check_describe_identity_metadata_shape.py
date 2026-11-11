"""describe-identity-metadata-shape."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "describe-identity-metadata-shape"
GROUP = 'identity-flow'
SERVICES = ['cognito-identity']

def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real": CHECK},
        **kwargs,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeIdentity returns the IdentityId plus creation/modification timestamps, and for an
    identity that has never been touched since creation the two timestamps are the same instant."""
    import datetime

    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True)
    identity_id = ev.get_id(IdentityPoolId=pool_id)["IdentityId"]
    desc = ev.describe_identity(IdentityId=identity_id)
    assert desc["IdentityId"] == identity_id, (
        f"expected IdentityId {identity_id!r}, got {desc.get('IdentityId')!r}"
    )
    assert not desc.get("Logins"), f"expected no linked logins, got {desc.get('Logins')!r}"

    creation = desc.get("CreationDate")
    modified = desc.get("LastModifiedDate")
    assert isinstance(creation, datetime.datetime), (
        f"expected CreationDate to be a datetime, got {creation!r}"
    )
    assert isinstance(modified, datetime.datetime), (
        f"expected LastModifiedDate to be a datetime, got {modified!r}"
    )
    assert creation == modified, (
        f"expected CreationDate == LastModifiedDate for an identity with no modification since "
        f"creation, got CreationDate={creation!r} LastModifiedDate={modified!r}"
    )

    # a repeated read must not advance either timestamp (state must not change on a read)
    desc2 = ev.describe_identity(IdentityId=identity_id)
    assert desc2["CreationDate"] == creation, (
        f"CreationDate changed across reads: {creation!r} != {desc2['CreationDate']!r}"
    )
    assert desc2["LastModifiedDate"] == modified, (
        f"LastModifiedDate changed across reads: {modified!r} != {desc2['LastModifiedDate']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
