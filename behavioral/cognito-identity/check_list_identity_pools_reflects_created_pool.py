"""list-identity-pools-reflects-created-pool."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-identity-pools-reflects-created-pool"
GROUP = 'lifecycle'
SERVICES = ['cognito-identity']

def _error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected success raises, so a
    target that still serves a deleted pool fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_pool(client, pool_id):
    """Teardown: a pool the check already deleted is gone, so not-found is the clean outcome."""
    try:
        client.delete_identity_pool(IdentityPoolId=pool_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise

def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns (pool_id, name)."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"env": "test", "owner": "fidelity-check"},
        **kwargs,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: _delete_pool(client, pool_id))
    return pool_id, name

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListIdentityPools enumerates a pool immediately after creation; Describe and Update are
    strongly consistent after delete."""
    ev = ctx.client("cognito-identity")
    pool_id, name = _create_pool(ev, ctx, allow_unauth=True)
    def _find_in_list():
        next_token = None
        for _ in range(50):  # bounded pagination walk
            kwargs = {"MaxResults": 60}
            if next_token:
                kwargs["NextToken"] = next_token
            page = ev.list_identity_pools(**kwargs)
            for entry in page.get("IdentityPools", []):
                if entry["IdentityPoolId"] == pool_id:
                    return entry
            next_token = page.get("NextToken")
            if not next_token:
                return None
        return None
    _deadline = time.monotonic() + 30
    found = None
    while time.monotonic() < _deadline:
        found = _find_in_list()
        if found:
            break
        time.sleep(2)
    else:
        raise AssertionError(f"poll condition not met within {30}s: {found!r}")
    assert found is not None, 'created pool did not appear in ListIdentityPools'
    assert found["IdentityPoolName"] == name, (
        f"expected ListIdentityPools entry name {name!r}, got {found['IdentityPoolName']!r}"
    )
    ev.delete_identity_pool(IdentityPoolId=pool_id)
    expected = f"IdentityPool '{pool_id}' not found."
    err, message = _error(lambda: ev.describe_identity_pool(IdentityPoolId=pool_id))
    assert err == "ResourceNotFoundException", (
        f"deleted pool must be gone from DescribeIdentityPool, got {err}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    err, message = _error(lambda: ev.update_identity_pool(
        IdentityPoolId=pool_id, IdentityPoolName=name, AllowUnauthenticatedIdentities=True
    ))
    assert err == "ResourceNotFoundException", (
        f"a mutation on the deleted pool must also fail not-found, got {err}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
