"""op-contract-unlinkDeveloperIdentity."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "op-contract-unlinkDeveloperIdentity"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]
NO_ACCESS_MESSAGE = "You do not have access to this identity"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After UnlinkDeveloperIdentity removes the identity's only login, LookupDeveloperIdentity
    answers NotAuthorizedException with the exact message, and a repeat unlink succeeds as a no-op
    leaving the same answer."""
    cidp = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("sim2real.dev.").replace("-", ".")
    pool_id = _create_identity_pool(ctx, dev_provider=dev_provider)

    dev_user_id = ctx.unique_name("sim2real-user-")
    created = cidp.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id,
        Logins={dev_provider: dev_user_id},
    )
    identity_id = created["IdentityId"]

    # The login is linked before unlinking. MaxResults is passed explicitly: an omitted value
    # defaults to 0 server-side, which fails the ">= 1" constraint.
    before = cidp.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=dev_user_id, MaxResults=60
    )
    assert before["IdentityId"] == identity_id, (
        f"expected lookup to resolve the freshly linked identity {identity_id}, got {before!r}"
    )

    # success path: unlink the developer login
    cidp.unlink_developer_identity(
        IdentityId=identity_id,
        IdentityPoolId=pool_id,
        DeveloperProviderName=dev_provider,
        DeveloperUserIdentifier=dev_user_id,
    )

    # The unlink becomes visible to LookupDeveloperIdentity asynchronously, so poll. With its only
    # login unlinked the identity is inaccessible, and the lookup answers NotAuthorizedException
    # (not ResourceNotFoundException).
    code_after, message_after = _poll_until_refused(
        lambda: cidp.lookup_developer_identity(
            IdentityPoolId=pool_id, DeveloperUserIdentifier=dev_user_id, MaxResults=60
        ),
        attempts=40,
        delay_s=5.0,
    )
    assert code_after == "NotAuthorizedException", (
        f"expected unlinked login to be unresolvable, got code={code_after}"
    )
    assert message_after == NO_ACCESS_MESSAGE, (
        f"expected message {NO_ACCESS_MESSAGE!r}, got {message_after!r}"
    )

    # Unlinking the already-unlinked login again succeeds as a no-op: UnlinkDeveloperIdentity acts
    # on the login mapping and does not gate on the identity being accessible.
    cidp.unlink_developer_identity(
        IdentityId=identity_id,
        IdentityPoolId=pool_id,
        DeveloperProviderName=dev_provider,
        DeveloperUserIdentifier=dev_user_id,
    )

    # terminal read: independent of the mutating unlink call itself. The no-op repeat must not
    # have resurrected the mapping or otherwise changed the identity's reachability.
    code_after_repeat, message_after_repeat = _error(
        lambda: cidp.lookup_developer_identity(
            IdentityPoolId=pool_id, DeveloperUserIdentifier=dev_user_id, MaxResults=60
        )
    )
    assert code_after_repeat == "NotAuthorizedException", (
        f"expected the no-op repeat unlink to leave the identity inaccessible, "
        f"got code={code_after_repeat}"
    )
    assert message_after_repeat == NO_ACCESS_MESSAGE, (
        f"expected message {NO_ACCESS_MESSAGE!r}, got {message_after_repeat!r}"
    )


def _create_identity_pool(ctx, *, dev_provider: str) -> str:
    cidp = ctx.client("cognito-identity")
    pool = cidp.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_pool_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=dev_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: cidp.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _poll_until_refused(fn, *, attempts: int = 10, delay_s: float = 1.5):
    """Call fn() until it raises a ClientError and return its (Error.Code, Error.Message);
    raise AssertionError if it still succeeds after ``attempts`` calls."""
    import time

    from botocore.exceptions import ClientError

    result = None
    for _ in range(attempts):
        try:
            result = fn()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        time.sleep(delay_s)
    raise AssertionError(f"expected the call to be refused, but it still succeeded with {result!r}")


def _error(fn) -> tuple[str, str | None]:
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
