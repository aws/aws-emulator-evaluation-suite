"""set-principal-tag-attribute-map-invalid-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-principal-tag-attribute-map-invalid-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetPrincipalTagAttributeMap rejects a principal tag key that exceeds the documented 128-char
    limit, and the rejected call leaves an already-established mapping untouched."""
    pool_id, provider_name = _create_pool_with_provider(ctx)
    ci = ctx.client("cognito-identity")

    # Positive control: a well-formed mapping is accepted on this exact pool/provider wiring, so
    # the negative below cannot be confused with "rejects every SetPrincipalTagAttributeMap call".
    valid_map = {"team": "custom:department"}
    ci.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id,
        IdentityProviderName=provider_name,
        UseDefaults=False,
        PrincipalTags=valid_map,
    )
    baseline = ci.get_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=provider_name
    )
    assert baseline["PrincipalTags"] == valid_map, (
        f"positive control failed: expected {valid_map!r}, got {baseline.get('PrincipalTags')!r}"
    )

    oversized_key = "k" * 200  # documented max key length is 128
    code, message = _error(
        lambda: ci.set_principal_tag_attribute_map(
            IdentityPoolId=pool_id,
            IdentityProviderName=provider_name,
            UseDefaults=False,
            PrincipalTags={oversized_key: "custom:department"},
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for oversized principal tag key, got {code!r}"
    )
    assert message == (
        f"1 validation error detected: Value '{{{oversized_key}=custom:department}}' at "
        "'principalTags' failed to satisfy "
        "constraint: Map keys must satisfy constraint: [Member must have length less than or "
        "equal to 128, Member must have length greater than or equal to 1]"
    ), (
        f"expected the exact refusal message AWS returns, got {message!r}"
    )

    # The rejected call must not have mutated the previously-established mapping.
    after = ci.get_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=provider_name
    )
    assert after["PrincipalTags"] == valid_map, (
        f"rejected SetPrincipalTagAttributeMap call mutated the mapping: {after.get('PrincipalTags')!r}"
    )


def _create_pool_with_provider(ctx):
    idp = ctx.client("cognito-idp")
    user_pool = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-up-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:check": CHECK},
    )["UserPool"]
    user_pool_id = user_pool["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=user_pool_id))

    client = idp.create_user_pool_client(
        UserPoolId=user_pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        GenerateSecret=False,
    )["UserPoolClient"]
    provider_name = f"cognito-idp.{ctx.region}.amazonaws.com/{user_pool_id}"

    ci = ctx.client("cognito-identity")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=True,
        CognitoIdentityProviders=[{"ProviderName": provider_name, "ClientId": client["ClientId"]}],
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id, provider_name


def _error(fn):
    """Call fn(); return (Code, Message) of the ClientError it raises, and fail if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
