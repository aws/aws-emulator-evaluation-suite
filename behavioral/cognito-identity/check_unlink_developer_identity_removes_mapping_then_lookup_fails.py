"""unlink-developer-identity-removes-mapping-then-lookup-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unlink-developer-identity-removes-mapping-then-lookup-fails"
GROUP = "state-machine"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UnlinkDeveloperIdentity removes a developer-user mapping so LookupDeveloperIdentity no longer resolves it."""
    ci = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("sim2real-devprov-")
    pool_id = _create_pool(ctx, DeveloperProviderName=dev_provider)
    dev_user_id = ctx.unique_name("sim2real-devuser-")

    resp = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dev_user_id}
    )
    identity_id = resp["IdentityId"]

    # MaxResults is server-defaulted to 0 when omitted, which real AWS rejects outright with
    # ValidationException ("Value '0' at 'maxResults' failed to satisfy constraint: Member must
    # have value greater than or equal to 1") -- pass an explicit, in-range value so the lookup
    # actually exercises the mapping instead of failing before it is reached.
    lookup = ci.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=dev_user_id, MaxResults=60
    )
    assert lookup["IdentityId"] == identity_id, lookup
    assert dev_user_id in lookup.get("DeveloperUserIdentifierList", []), lookup

    ci.unlink_developer_identity(
        IdentityId=identity_id,
        IdentityPoolId=pool_id,
        DeveloperProviderName=dev_provider,
        DeveloperUserIdentifier=dev_user_id,
    )

    # This was the identity's only login, so unlinking it leaves the identity itself
    # inaccessible. Real AWS does not treat "unlinked" the same as "never existed": it reports
    # NotAuthorizedException for a lookup against an unlinked identifier, not
    # ResourceNotFoundException. The reverse (DeveloperUserIdentifier -> IdentityId) index can lag
    # behind the UnlinkDeveloperIdentity call, so poll for the expected error instead of asserting
    # on the very first attempt.
    code, message = _poll_for_error(
        lambda: ci.lookup_developer_identity(
            IdentityPoolId=pool_id, DeveloperUserIdentifier=dev_user_id, MaxResults=60
        ),
        expected_code="NotAuthorizedException",
    )
    assert code == "NotAuthorizedException", (
        f"expected the unlinked developer user identifier to no longer resolve, got {code!r}"
    )
    assert message == "You do not have access to this identity", message


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


def _create_pool(ctx, **extra) -> str:
    ci = ctx.client("cognito-identity")
    name = extra.pop("IdentityPoolName", None) or ctx.unique_name("sim2real-behav-")
    allow_unauth = extra.pop("AllowUnauthenticatedIdentities", True)
    resp = ci.create_identity_pool(
        IdentityPoolName=name, AllowUnauthenticatedIdentities=allow_unauth, **extra
    )
    pool_id = resp["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
