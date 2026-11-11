"""get-principal-tag-attribute-map-use-defaults-flag-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-principal-tag-attribute-map-use-defaults-flag-round-trip"
GROUP = "data-plane"
SERVICES = ["cognito-identity"]


def _error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetPrincipalTagAttributeMap with UseDefaults=true and an empty PrincipalTags
    map is faithfully reflected by GetPrincipalTagAttributeMap rather than defaulting
    UseDefaults to false."""
    ci = ctx.client("cognito-identity")
    provider_name = f"cognito-idp.{ctx.region}.amazonaws.com/{ctx.region}_sim2realfake02"
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-"),
        AllowUnauthenticatedIdentities=True,
        CognitoIdentityProviders=[
            {"ProviderName": provider_name, "ClientId": "sim2realfakeclientid456"}
        ],
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]

    def _cleanup():
        try:
            ci.delete_identity_pool(IdentityPoolId=pool_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    set_resp = ci.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id,
        IdentityProviderName=provider_name,
        UseDefaults=True,
        PrincipalTags={},
    )
    assert set_resp["UseDefaults"] is True, (
        f"expected UseDefaults=True to be honored by SetPrincipalTagAttributeMap, "
        f"got {set_resp['UseDefaults']!r}"
    )
    # For a Cognito user-pool provider, UseDefaults=True auto-populates a non-empty
    # default claim -> tag mapping (see "Default provider mappings" in the developer
    # guide) even though we submitted an empty PrincipalTags map -- UseDefaults is not
    # a no-op flag, it actively supplies AWS-managed defaults rather than leaving the
    # map empty.
    set_tags = set_resp.get("PrincipalTags") or {}
    assert set_tags, (
        f"expected UseDefaults=True to populate a non-empty default claim/tag "
        f"mapping instead of leaving PrincipalTags empty, got {set_tags!r}"
    )

    got = ci.get_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=provider_name
    )
    assert got["UseDefaults"] is True, (
        f"UseDefaults was set to True but GetPrincipalTagAttributeMap returned "
        f"{got['UseDefaults']!r}"
    )
    # GetPrincipalTagAttributeMap must faithfully reflect the same default mapping
    # that SetPrincipalTagAttributeMap's response reported, not diverge from it.
    assert got.get("PrincipalTags") == set_tags, (
        f"GetPrincipalTagAttributeMap PrincipalTags {got.get('PrincipalTags')!r} "
        f"diverges from what SetPrincipalTagAttributeMap reported {set_tags!r}"
    )

    ci.delete_identity_pool(IdentityPoolId=pool_id)
    expected = f"IdentityPool '{pool_id}' not found."
    describe_code, describe_message = _error(
        lambda: ci.describe_identity_pool(IdentityPoolId=pool_id)
    )
    assert describe_code == "ResourceNotFoundException", (
        f"expected a deleted identity pool to be gone from DescribeIdentityPool, "
        f"got error code {describe_code!r}"
    )
    assert describe_message == expected, (
        f"expected message {expected!r}, got {describe_message!r}"
    )
    get_after_delete_code, get_after_delete_message = _error(
        lambda: ci.get_principal_tag_attribute_map(
            IdentityPoolId=pool_id, IdentityProviderName=provider_name
        )
    )
    assert get_after_delete_code == "ResourceNotFoundException", (
        f"expected GetPrincipalTagAttributeMap on a deleted identity pool to fail with "
        f"ResourceNotFoundException, got {get_after_delete_code!r}"
    )
    assert get_after_delete_message == expected, (
        f"expected message {expected!r}, got {get_after_delete_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
