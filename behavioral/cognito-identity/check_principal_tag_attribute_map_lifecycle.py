"""principal-tag-attribute-map-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "principal-tag-attribute-map-lifecycle"
GROUP = "state-machine"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetPrincipalTagAttributeMap then Get reflects the mapping; UseDefaults=True reports the
    default client/username map; once the identity pool is deleted, Get, Set and
    DescribeIdentityPool on it raise ResourceNotFoundException naming the pool."""
    pool_id, provider_name = _create_pool_with_provider(ctx)
    ci = ctx.client("cognito-identity")

    set_resp = ci.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id,
        IdentityProviderName=provider_name,
        UseDefaults=False,
        PrincipalTags={"department": "custom:department", "team": "custom:team"},
    )
    assert set_resp["UseDefaults"] is False, set_resp
    assert set_resp["PrincipalTags"] == {
        "department": "custom:department",
        "team": "custom:team",
    }, set_resp

    get_resp = ci.get_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=provider_name
    )
    assert get_resp["UseDefaults"] is False, get_resp
    assert get_resp["PrincipalTags"] == {
        "department": "custom:department",
        "team": "custom:team",
    }, get_resp

    # Switching to UseDefaults=True with an empty custom map resets the mapping to defaults.
    ci.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id,
        IdentityProviderName=provider_name,
        UseDefaults=True,
        PrincipalTags={},
    )
    reset_resp = ci.get_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=provider_name
    )
    assert reset_resp["UseDefaults"] is True, reset_resp
    # UseDefaults=True reports the default attribute mapping, not an empty dict, and the
    # custom mapping is gone.
    reset_tags = reset_resp.get("PrincipalTags", {})
    assert "department" not in reset_tags and "team" not in reset_tags, (
        f"expected custom principal tag mapping cleared after switching to defaults, got {reset_resp}"
    )
    assert reset_tags == {"client": "aud", "username": "sub"}, (
        f"expected the default principal tag map {{'client': 'aud', 'username': 'sub'}}, got {reset_resp}"
    )

    # Deleting the identity pool removes its principal tag map with it.
    ci.delete_identity_pool(IdentityPoolId=pool_id)
    expected = f"IdentityPool '{pool_id}' not found."
    got_get = _error(
        lambda: ci.get_principal_tag_attribute_map(
            IdentityPoolId=pool_id, IdentityProviderName=provider_name
        )
    )
    assert got_get == ("ResourceNotFoundException", expected), (
        f"expected GetPrincipalTagAttributeMap on the deleted pool to raise "
        f"('ResourceNotFoundException', {expected!r}), got {got_get!r}"
    )
    got_set = _error(
        lambda: ci.set_principal_tag_attribute_map(
            IdentityPoolId=pool_id,
            IdentityProviderName=provider_name,
            UseDefaults=False,
            PrincipalTags={"department": "custom:department"},
        )
    )
    assert got_set == ("ResourceNotFoundException", expected), (
        f"expected SetPrincipalTagAttributeMap on the deleted pool to raise "
        f"('ResourceNotFoundException', {expected!r}), got {got_set!r}"
    )
    got_describe = _error(lambda: ci.describe_identity_pool(IdentityPoolId=pool_id))
    assert got_describe == ("ResourceNotFoundException", expected), (
        f"expected DescribeIdentityPool on the deleted pool to raise "
        f"('ResourceNotFoundException', {expected!r}), got {got_describe!r}"
    )


def _create_pool_with_provider(ctx):
    idp = ctx.client("cognito-idp")
    user_pool = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-up-"),
        UserPoolTags={"sim2real": CHECK},
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
    ctx.on_cleanup(lambda: _delete_identity_pool(ci, pool_id))
    return pool_id, provider_name


def _delete_identity_pool(ci, pool_id):
    """Teardown: the check deletes the pool itself, so not-found is the clean outcome."""
    try:
        ci.delete_identity_pool(IdentityPoolId=pool_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
