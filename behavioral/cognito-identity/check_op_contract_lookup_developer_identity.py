"""op-contract-lookupDeveloperIdentity."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "op-contract-lookupDeveloperIdentity"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """LookupDeveloperIdentity resolves a developer identity by IdentityId or by
    DeveloperUserIdentifier, and rejects a request supplying neither."""
    cidp = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("sim2real.dev.").replace("-", ".")
    pool_id = _create_identity_pool(ctx, dev_provider=dev_provider)

    dev_user_id = ctx.unique_name("sim2real-user-")
    created = cidp.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id,
        Logins={dev_provider: dev_user_id},
    )
    identity_id = created["IdentityId"]

    # lookup by IdentityId -> reports the linked developer user identifier
    # Note: real AWS treats MaxResults as effectively required for LookupDeveloperIdentity —
    # an omitted value is defaulted server-side to 0, which then fails the ">= 1" constraint.
    # Always pass it explicitly.
    by_identity = cidp.lookup_developer_identity(
        IdentityPoolId=pool_id, IdentityId=identity_id, MaxResults=60
    )
    assert by_identity["IdentityId"] == identity_id, (
        f"expected IdentityId {identity_id}, got {by_identity.get('IdentityId')}"
    )
    assert dev_user_id in by_identity.get("DeveloperUserIdentifierList", []), (
        f"expected {dev_user_id} in {by_identity.get('DeveloperUserIdentifierList')}"
    )

    # lookup by DeveloperUserIdentifier -> resolves back to the same IdentityId
    by_user = cidp.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=dev_user_id, MaxResults=60
    )
    assert by_user["IdentityId"] == identity_id, (
        f"expected IdentityId {identity_id}, got {by_user.get('IdentityId')}"
    )

    # error boundary: neither IdentityId nor DeveloperUserIdentifier supplied
    code, message = _error(
        lambda: cidp.lookup_developer_identity(IdentityPoolId=pool_id, MaxResults=60)
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected_message = "Please specify either an identity id or developer user identifier"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


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


def _error(fn) -> tuple[str, str | None]:
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it succeeded with {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
