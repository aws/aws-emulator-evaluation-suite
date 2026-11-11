"""unlink-developer-identity-not-linked-is-an-idempotent-no-op."""
from __future__ import annotations

import time
import uuid
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "unlink-developer-identity-not-linked-is-an-idempotent-no-op"
GROUP = "state-machine"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Repeating UnlinkDeveloperIdentity for a mapping that no longer exists is a no-op, and
    does not resurrect (or otherwise change) the removed mapping."""
    client = ctx.client("cognito-identity")
    dev_provider = f"login.{ctx.unique_name('sim2real')}"
    pool_id = _create_pool(
        ctx, client, DeveloperProviderName=dev_provider, IdentityPoolTags={"sim2real": CHECK}
    )

    dev_user = f"user-{uuid.uuid4()}"
    identity_id = client.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dev_user}
    )["IdentityId"]

    # positive control: the mapping is live before we touch it
    live = client.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=dev_user, MaxResults=1
    )
    assert live["IdentityId"] == identity_id, live

    # positive control: the first unlink succeeds while the mapping is live
    client.unlink_developer_identity(
        IdentityId=identity_id,
        IdentityPoolId=pool_id,
        DeveloperProviderName=dev_provider,
        DeveloperUserIdentifier=dev_user,
    )

    # the mapping is now gone. Unlike LookupDeveloperIdentity (which always demands an
    # *active* link and rejects anything else with NotAuthorizedException), real AWS treats
    # UnlinkDeveloperIdentity as idempotent for a pairing that is no longer linked: since the
    # identity itself still exists, repeating the exact same unlink call simply succeeds again
    # with no error -- it does not raise NotAuthorizedException, ResourceNotFoundException, or
    # ResourceConflictException for this case.
    client.unlink_developer_identity(
        IdentityId=identity_id,
        IdentityPoolId=pool_id,
        DeveloperProviderName=dev_provider,
        DeveloperUserIdentifier=dev_user,
    )

    # effect absent: the repeat (no-op) unlink call must not resurrect the mapping -- the
    # lookup keeps failing exactly as it does after any unlink. The removal itself is not
    # guaranteed to be instantly consistent, so poll rather than assuming the very next call
    # already observes it.
    code2, message2 = _poll_for_error(
        lambda: client.lookup_developer_identity(
            IdentityPoolId=pool_id, DeveloperUserIdentifier=dev_user, MaxResults=1
        ),
        "NotAuthorizedException",
    )
    assert code2 == "NotAuthorizedException", (
        f"repeat unlink resurrected the developer user id mapping, lookup got {code2}"
    )
    assert message2 == "You do not have access to this identity", message2


def _create_pool(ctx, client, **extra_fields: Any) -> str:
    params = {
        "IdentityPoolName": ctx.unique_name("sim2real-idp-"),
        "AllowUnauthenticatedIdentities": True,
    }
    params.update(extra_fields)
    pool_id = client.create_identity_pool(**params)["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
