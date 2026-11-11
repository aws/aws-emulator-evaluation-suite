"""principal-tag-attribute-map-invalid-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "principal-tag-attribute-map-invalid-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetPrincipalTagAttributeMap with a tag key over the 128-character limit is refused with
    ValidationException and the exact constraint message, and GetPrincipalTagAttributeMap still
    returns the previous valid mapping."""
    ci = ctx.client("cognito-identity")
    # IdentityProviderName must be a supported login provider (or a user pool / SAML / OIDC
    # provider); a DeveloperProviderName is refused ("Provider ... not configured for Identity Pool").
    login_provider = "graph.facebook.com"
    pool_id = _create_pool(ctx, ci, login_provider=login_provider)

    # Positive control: a well-formed custom key is accepted.
    valid_map = {"team": "custom:team"}
    ci.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id,
        IdentityProviderName=login_provider,
        UseDefaults=False,
        PrincipalTags=valid_map,
    )
    baseline = ci.get_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=login_provider
    )
    assert baseline["PrincipalTags"] == valid_map, (
        f"expected the positive-control mapping {valid_map!r} to round-trip, got {baseline!r}"
    )

    # Negative: a tag key exceeding the PrincipalTagID max length (128 chars) must
    # be rejected.
    invalid_key = "d" * 200
    invalid_map = {invalid_key: "custom:department"}
    code, message = _error(
        lambda: ci.set_principal_tag_attribute_map(
            IdentityPoolId=pool_id,
            IdentityProviderName=login_provider,
            UseDefaults=False,
            PrincipalTags=invalid_map,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        f"1 validation error detected: Value '{{{invalid_key}=custom:department}}' at "
        "'principalTags' failed to satisfy constraint: Map keys must satisfy constraint: "
        "[Member must have length less than or equal to 128, "
        "Member must have length greater than or equal to 1]"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The rejected call must not have mutated the stored mapping.
    after = ci.get_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=login_provider
    )
    assert after["PrincipalTags"] == valid_map, (
        f"rejected SetPrincipalTagAttributeMap call mutated the stored mapping: "
        f"expected it to remain {valid_map!r}, got {after!r}"
    )


def _create_pool(ctx, ci, *, unauth: bool = True, login_provider: str | None = None) -> str:
    kwargs = {
        "IdentityPoolName": ctx.unique_name("sim2real-behav-pool-"),
        "AllowUnauthenticatedIdentities": unauth,
        "IdentityPoolTags": {"sim2real": CHECK},
    }
    if login_provider:
        kwargs["SupportedLoginProviders"] = {login_provider: ctx.unique_name("app-")}
    pool_id = ci.create_identity_pool(**kwargs)["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected SetPrincipalTagAttributeMap to reject the oversized key, "
        f"but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
