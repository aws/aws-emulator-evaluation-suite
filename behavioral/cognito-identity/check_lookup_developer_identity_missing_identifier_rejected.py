"""lookup-developer-identity-missing-identifier-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "lookup-developer-identity-missing-identifier-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """LookupDeveloperIdentity without a DeveloperUserIdentifier or IdentityId returns InvalidParameterException."""
    ci = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("sim2real-dev-")
    pool_id = _create_pool(ctx, DeveloperProviderName=dev_provider)

    dev_user_id = ctx.unique_name("sim2real-user-")
    identity_id = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dev_user_id}
    )["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))

    # positive control: the pool, provider and credentials are otherwise healthy for
    # LookupDeveloperIdentity, so the negative below cannot pass merely because every
    # call to the operation is being refused.
    looked_up = ci.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=dev_user_id, MaxResults=1
    )
    assert looked_up["IdentityId"] == identity_id, (
        f"expected {identity_id}, got {looked_up.get('IdentityId')}"
    )

    code, message = _error(
        lambda: ci.lookup_developer_identity(IdentityPoolId=pool_id, MaxResults=1)
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for a missing identifier, got {code!r}"
    )
    expected_message = "Please specify either an identity id or developer user identifier"
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )


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


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
