"""set-principal-tag-attribute-map-invalid-keys-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-principal-tag-attribute-map-invalid-keys-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetPrincipalTagAttributeMap with two keys over the 128-character PrincipalTagID limit is
    refused with ValidationException and the exact constraint message, and
    GetPrincipalTagAttributeMap still returns the previous mapping."""
    ci = ctx.client("cognito-identity")
    login_provider = "graph.facebook.com"
    pool_id = _create_pool(ci, ctx, login_provider=login_provider)

    # Positive control: a well-formed mapping is accepted.
    valid_map = {"team": "custom:team", "dept": "custom:department"}
    ci.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id,
        IdentityProviderName=login_provider,
        UseDefaults=False,
        PrincipalTags=valid_map,
    )
    baseline = ci.get_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=login_provider
    )
    assert baseline["PrincipalTags"] == valid_map, baseline

    # Negative: a map with TWO keys that each exceed the 128-char PrincipalTagID
    # limit must be rejected as a whole.
    oversized_a = "a" * 129
    oversized_b = "b" * 200
    invalid_map = {oversized_a: "custom:a", oversized_b: "custom:b"}
    code, message = _error(
        lambda: ci.set_principal_tag_attribute_map(
            IdentityPoolId=pool_id,
            IdentityProviderName=login_provider,
            UseDefaults=False,
            PrincipalTags=invalid_map,
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a map with multiple oversized "
        f"principal tag keys, got {code!r}"
    )
    # AWS renders the rejected map in its own stable key order: b before a.
    assert message == (
        f"1 validation error detected: Value '{{{oversized_b}=custom:b, {oversized_a}=custom:a}}' "
        "at 'principalTags' failed to satisfy "
        "constraint: Map keys must satisfy constraint: [Member must have length less than or "
        "equal to 128, Member must have length greater than or equal to 1]"
    ), (
        f"expected the exact refusal message AWS returns, got {message!r}"
    )

    # The rejected call must not have mutated the stored mapping -- neither
    # oversized key leaked in, and the prior valid mapping is intact.
    after = ci.get_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=login_provider
    )
    assert after["PrincipalTags"] == valid_map, after


def _create_pool(ci, ctx, *, login_provider: str) -> str:
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-"),
        AllowUnauthenticatedIdentities=True,
        SupportedLoginProviders={login_provider: ctx.unique_name("app-")},
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


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
