"""delete-identities-ignores-unknown-ids."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-identities-ignores-unknown-ids"
GROUP = 'identity-flow'
SERVICES = ['cognito-identity']

def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name, AllowUnauthenticatedIdentities=allow_unauth, **kwargs
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteIdentities deletes valid ids and silently ignores ids that were never issued."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True)
    id1 = ev.get_id(IdentityPoolId=pool_id)["IdentityId"]
    id2 = ev.get_id(IdentityPoolId=pool_id)["IdentityId"]
    bogus_id = f"{ctx.region}:00000000-0000-0000-0000-000000000000"
    resp = ev.delete_identities(IdentityIdsToDelete=[id1, id2, bogus_id])
    unprocessed = {u["IdentityId"]: u.get("ErrorCode") for u in resp.get("UnprocessedIdentityIds", [])}
    assert id1 not in unprocessed, f"valid identity {id1} unexpectedly unprocessed"
    assert id2 not in unprocessed, f"valid identity {id2} unexpectedly unprocessed"
    assert not unprocessed, (
        f"expected no UnprocessedIdentityIds for a batch of well-formed ids, got {unprocessed}"
    )
    for real_id in (id1, id2):
        err, message = _error(lambda i=real_id: ev.describe_identity(IdentityId=i))
        assert err == "ResourceNotFoundException", f"expected deleted identity {real_id} to 404, got {err}"
        expected = f"Identity '{real_id}' not found."
        assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
