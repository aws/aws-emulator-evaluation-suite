"""set-principal-tag-attribute-map-exceeds-max-mappings-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-principal-tag-attribute-map-exceeds-max-mappings-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetPrincipalTagAttributeMap rejects 51 PrincipalTags (maximum 50) with ValidationException
    and persists nothing; exactly 50 entries are accepted and read back in full."""
    region = ctx.region
    cidp = ctx.client("cognito-idp")
    identity = ctx.client("cognito-identity")

    pool_id, client_id = _create_user_pool_client(ctx, cidp)
    provider_name = f"cognito-idp.{region}.amazonaws.com/{pool_id}"

    ci_pool_id = identity.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-cipool-"),
        AllowUnauthenticatedIdentities=True,
        CognitoIdentityProviders=[
            {"ProviderName": provider_name, "ClientId": client_id, "ServerSideTokenCheck": False}
        ],
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: identity.delete_identity_pool(IdentityPoolId=ci_pool_id))

    too_many = {f"tag{i}": f"claim{i}" for i in range(51)}
    code, message = _error(
        lambda: identity.set_principal_tag_attribute_map(
            IdentityPoolId=ci_pool_id, IdentityProviderName=provider_name, PrincipalTags=too_many
        )
    )
    assert code == "ValidationException", f"CODE={code}"
    # AWS renders the rejected map in its own stable key order.
    rendered = ", ".join(f"tag{i}=claim{i}" for i in _RENDERED_ORDER)
    assert message == (
        f"1 validation error detected: Value '{{{rendered}}}' at 'principalTags' failed to "
        "satisfy constraint: Member must have length less than or equal to 50"
    ), (
        f"expected the exact refusal message AWS returns, got {message!r}"
    )

    current_code, current_message = _error(
        lambda: identity.get_principal_tag_attribute_map(
            IdentityPoolId=ci_pool_id, IdentityProviderName=provider_name
        )
    )
    assert current_code == "ResourceNotFoundException", (
        f"the rejected over-limit map must not be persisted, got current_code={current_code}"
    )
    assert current_message == f"No Principal Tags configured for Provider {provider_name}", (
        f"expected the exact refusal message AWS returns, got {current_message!r}"
    )

    max_ok = {f"tag{i}": f"claim{i}" for i in range(50)}
    identity.set_principal_tag_attribute_map(
        IdentityPoolId=ci_pool_id, IdentityProviderName=provider_name, PrincipalTags=max_ok
    )
    stored = identity.get_principal_tag_attribute_map(
        IdentityPoolId=ci_pool_id, IdentityProviderName=provider_name
    )["PrincipalTags"]
    assert stored == max_ok, f"exactly-50 positive control did not round-trip: stored={stored!r}"


# The key order AWS uses when it renders the 51-entry map in its refusal message.
_RENDERED_ORDER = (
        40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 39, 50, 10,
        11, 12, 13, 14, 15, 16, 20, 21, 22, 23, 24, 25, 26,
        27, 17, 18, 19, 0, 1, 30, 31, 8, 32, 9, 33, 6,
        34, 7, 35, 4, 36, 5, 2, 37, 3, 38, 28, 29,
)


def _error(fn):
    """Call fn(); return (Code, Message) of the ClientError it raises, and fail if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_user_pool_client(ctx, cidp: Any) -> tuple[str, str]:
    pool_id = cidp.create_user_pool(PoolName=ctx.unique_name("sim2real-userpool-"))["UserPool"][
        "Id"
    ]
    ctx.on_cleanup(lambda: cidp.delete_user_pool(UserPoolId=pool_id))
    client_id = cidp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-client-"), GenerateSecret=False
    )["UserPoolClient"]["ClientId"]
    return pool_id, client_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
