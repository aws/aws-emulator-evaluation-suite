"""unlink-with-an-unknown-developer-provider-is-rejected-and-the-login-survives."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unlink-with-an-unknown-developer-provider-is-rejected-and-the-login-survives"
GROUP = 'overly-permissive'
SERVICES = ['cognito-identity']

# UnlinkDeveloperIdentity validates the developer PROVIDER against the pool's configured one and
# refuses a mismatch with InvalidParameterException. A mismatched developer USER identifier is not
# an error: the call returns 200 and is a no-op, so only the provider is broken here.
EXPECTED_CODE = "InvalidParameterException"
EXPECTED_MESSAGE = "This identity pool does not support the specified developer provider."


def _refusal(fn, what):
    """Call fn(); return (Code, Message) when it is refused, and raise when it succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"{what} must be refused, but the call succeeded")


def _poll_until(fn, pred, timeout_s=60.0, interval_s=3.0, description="condition"):
    """Poll fn() until pred(result) or the deadline; ClientErrors count as not-yet."""
    deadline = time.time() + timeout_s
    last = None
    last_exc = None
    while time.time() < deadline:
        try:
            last = fn()
            if pred(last):
                return last
            last_exc = None
        except ClientError as exc:
            last_exc = exc
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}: last={last!r} err={last_exc!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UnlinkDeveloperIdentity naming a developer provider the pool does not have is refused with
    InvalidParameterException and leaves the identity's login attached and resolvable, while the
    same call with the pool's own provider removes it.
    """
    ci = ctx.client("cognito-identity")
    developer_provider = ctx.unique_name("sim2real-behav-unlink-dev-")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_behav_unlink_").replace("-", "_"),
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=developer_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    developer_user_id = ctx.unique_name("sim2real-behav-unlink-user-")
    identity_id = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={developer_provider: developer_user_id}
    )["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))

    logins_before = ci.describe_identity(IdentityId=identity_id).get("Logins", [])
    assert developer_provider in logins_before, (
        f"the identity should start out carrying the developer login, DescribeIdentity reports "
        f"{logins_before!r}"
    )
    # MaxResults is optional per the model but real AWS server-defaults it to 0 and then rejects
    # that as out of range, so it is always passed explicitly.
    lookup_before = ci.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=developer_user_id, MaxResults=60
    )
    assert lookup_before["IdentityId"] == identity_id, (
        f"LookupDeveloperIdentity resolved {developer_user_id!r} to "
        f"{lookup_before['IdentityId']!r}, expected {identity_id!r}"
    )

    # ---- break exactly one field: the developer provider name
    unknown_provider = developer_provider + "-unknown"
    code, message = _refusal(
        lambda: ci.unlink_developer_identity(
            IdentityId=identity_id,
            IdentityPoolId=pool_id,
            DeveloperProviderName=unknown_provider,
            DeveloperUserIdentifier=developer_user_id,
        ),
        f"UnlinkDeveloperIdentity naming the provider {unknown_provider!r}, which this pool does "
        f"not have,",
    )
    assert code == EXPECTED_CODE, (
        f"expected {EXPECTED_CODE!r} for an unknown developer provider, got {code!r}: {message!r}"
    )
    assert message == EXPECTED_MESSAGE, (
        f"expected the message {EXPECTED_MESSAGE!r} for an unknown developer provider, got "
        f"{message!r}"
    )

    # ---- the effect is absent: the login is untouched and still resolvable
    logins_after_reject = ci.describe_identity(IdentityId=identity_id).get("Logins", [])
    assert logins_after_reject == logins_before, (
        f"logins changed on a rejected unlink: {logins_before!r} -> {logins_after_reject!r}"
    )
    lookup_after_reject = ci.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=developer_user_id, MaxResults=60
    )
    assert lookup_after_reject["IdentityId"] == identity_id, (
        f"the developer user identifier stopped resolving to {identity_id!r} after a REJECTED "
        f"unlink: {lookup_after_reject['IdentityId']!r}"
    )

    # ---- positive control: the same call with the pool's own provider does remove the login
    ci.unlink_developer_identity(
        IdentityId=identity_id,
        IdentityPoolId=pool_id,
        DeveloperProviderName=developer_provider,
        DeveloperUserIdentifier=developer_user_id,
    )
    logins_after_unlink = _poll_until(
        lambda: ci.describe_identity(IdentityId=identity_id).get("Logins", []),
        lambda logins: developer_provider not in logins,
        timeout_s=60.0,
        description="the unlinked developer provider to disappear from the identity's logins",
    )
    assert developer_provider not in logins_after_unlink, (
        f"logins after a correct unlink were {logins_after_unlink!r}, expected the developer "
        f"provider {developer_provider!r} to be gone"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
