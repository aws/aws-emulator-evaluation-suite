"""unlink-developer-identity-removes-login."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "unlink-developer-identity-removes-login"
GROUP = "identity-lifecycle"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UnlinkDeveloperIdentity detaches the developer login; the identity's Logins no longer include
    the provider and LookupDeveloperIdentity by that user identifier stops resolving to it."""
    ci = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("sim2real-dev-")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-"),
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=dev_provider,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    dev_user = ctx.unique_name("user-")
    identity_id = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dev_user}
    )["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))

    described = ci.describe_identity(IdentityId=identity_id)
    assert dev_provider in described.get("Logins", []), (
        f"expected developer provider {dev_provider!r} in Logins before unlink, "
        f"got {described.get('Logins')!r}"
    )

    ci.unlink_developer_identity(
        IdentityId=identity_id,
        IdentityPoolId=pool_id,
        DeveloperProviderName=dev_provider,
        DeveloperUserIdentifier=dev_user,
    )

    described_after = ci.describe_identity(IdentityId=identity_id)
    assert dev_provider not in described_after.get("Logins", []), (
        f"developer provider {dev_provider!r} still present after unlink"
    )

    # MaxResults is optional per the API model, but real AWS rejects LookupDeveloperIdentity
    # calls that omit it with "ValidationException: Value '0' at 'maxResults' failed to satisfy
    # constraint..." (it's server-side defaulted to 0) -- pass an explicit, in-range value so the
    # poll actually observes the expected error instead of a spurious ValidationException.
    #
    # Unlinking the developer identifier and it having *never existed* are not treated the same
    # by real AWS: once a developer user identifier is unlinked from an identity (and that was
    # its only login), the identity becomes inaccessible via that identifier, and real AWS reports
    # subsequent lookups against it as NotAuthorizedException rather than ResourceNotFoundException.
    code, message = _poll_for_error(
        lambda: ci.lookup_developer_identity(
            IdentityPoolId=pool_id, DeveloperUserIdentifier=dev_user, MaxResults=60
        ),
        expected_code="NotAuthorizedException",
    )
    assert code == "NotAuthorizedException", (
        f"expected the unlinked developer user identifier to no longer resolve, got {code!r}"
    )
    assert message == "You do not have access to this identity", (
        f"unexpected refusal message {message!r}"
    )


def _poll_for_error(fn, expected_code, timeout=30, interval=2):
    """Poll fn() until it fails with expected_code and return that (Code, Message).

    The reverse (DeveloperUserIdentifier -> IdentityId) index used by LookupDeveloperIdentity can
    lag behind UnlinkDeveloperIdentity, so a success or another code is retried until the
    deadline, which raises with the last outcome seen.
    """
    import time

    from botocore.exceptions import ClientError

    deadline = time.time() + timeout
    while True:
        try:
            last = ("succeeded", fn())
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == expected_code:
                return err["Code"], err.get("Message")
            last = (err["Code"], err.get("Message"))
        if time.time() >= deadline:
            raise AssertionError(
                f"no {expected_code} within {timeout}s; last outcome {last!r}"
            )
        time.sleep(interval)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
