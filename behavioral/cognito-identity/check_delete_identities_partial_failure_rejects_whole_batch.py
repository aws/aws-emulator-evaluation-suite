"""delete-identities-partial-failure-rejects-whole-batch."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-identities-partial-failure-rejects-whole-batch"
GROUP = 'overly-permissive'
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
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real": CHECK},
        **kwargs,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteIdentities rejects a whole batch containing a badly-formatted id (ValidationException);
    a well-formed nonexistent id co-batched with a real one is a no-op, not listed in
    UnprocessedIdentityIds, and the real identity is still deleted."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True)
    valid_id = ev.get_id(IdentityPoolId=pool_id)["IdentityId"]

    # A batch containing a badly-formatted id must be rejected outright, not partially processed.
    malformed_id = "not-a-real-identity-id"
    code, message = _error(
        lambda: ev.delete_identities(IdentityIdsToDelete=[valid_id, malformed_id])
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        f"1 validation error detected: Value '[{valid_id}, {malformed_id}]' at "
        "'identityIdsToDelete' failed to satisfy constraint: Member must satisfy constraint: "
        "[Member must have length less than or equal to 55, Member must have length greater "
        "than or equal to 1, Member must satisfy regular expression pattern: [\\w-]+:[0-9a-f-]+]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Well-formed (REGION:GUID) but never actually issued by GetId: deleting it alongside a real
    # id is a no-op for the nonexistent one, not an error.
    nonexistent_id = f"{ctx.region}:00000000-0000-0000-0000-000000000000"
    del_resp = ev.delete_identities(IdentityIdsToDelete=[valid_id, nonexistent_id])
    unprocessed = del_resp.get("UnprocessedIdentityIds", [])
    assert unprocessed == [], f"expected no unprocessed ids for a well-formed nonexistent id, got {unprocessed}"

    # The valid identity really was deleted.
    code, message = _error(lambda: ev.describe_identity(IdentityId=valid_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"Identity '{valid_id}' not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
