"""unlink-developer-identity-removes-mapping."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unlink-developer-identity-removes-mapping"
GROUP = 'developer-identity'
SERVICES = ['cognito-identity']

def _poll_for_error(fn, expected_code, timeout=30.0, interval=2.0):
    """Retry fn() until it raises a ClientError with expected_code and return its (Code, Message).
    The reverse (DeveloperUserIdentifier -> IdentityId) index can lag an unlink, so a success or
    another code is retried until the deadline, which raises."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            result = fn()
            last = f"SUCCEEDED and returned {result!r}"
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == expected_code:
                return err.get("Code"), err.get("Message")
            last = f"{err.get('Code')}: {err.get('Message')!r}"
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected {expected_code} within {timeout}s, the last call {last}")
        time.sleep(interval)

def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name, AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real": CHECK}, **kwargs
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UnlinkDeveloperIdentity removes the dev-provider login association from an identity."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True, DeveloperProviderName="login.myapp")
    user_id = ctx.unique_name("sim2real-behav-devuser-")
    identity_id = ev.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={"login.myapp": user_id}
    )["IdentityId"]

    # positive control: the mapping resolves while still linked, so the rejection
    # asserted below cannot be mistaken for "LookupDeveloperIdentity rejects everything".
    before = ev.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=user_id, MaxResults=10
    )
    assert before["IdentityId"] == identity_id, before

    ev.unlink_developer_identity(
        IdentityId=identity_id,
        IdentityPoolId=pool_id,
        DeveloperProviderName="login.myapp",
        DeveloperUserIdentifier=user_id,
    )
    # Unlinking a developer identifier and it having never existed are not treated the
    # same by real AWS: once the identity's only login is removed it becomes
    # inaccessible, and real AWS reports subsequent lookups against it as
    # NotAuthorizedException rather than ResourceNotFoundException.
    err, message = _poll_for_error(
        lambda: ev.lookup_developer_identity(
            IdentityPoolId=pool_id, DeveloperUserIdentifier=user_id, MaxResults=10
        ),
        expected_code="NotAuthorizedException",
        timeout=40.0,
    )
    assert err == "NotAuthorizedException", (
        f"expected unlinked developer user identifier lookup to be rejected with "
        f"NotAuthorizedException, got {err}"
    )
    assert message == "You do not have access to this identity", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
