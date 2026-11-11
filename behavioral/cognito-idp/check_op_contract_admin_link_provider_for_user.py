"""op-contract-adminLinkProviderForUser."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-adminLinkProviderForUser"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_PASSWORD = "TestPassw0rd!23"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminLinkProviderForUser adds the federated identity to the native user's identities, linking it
    to a second user while the first link stands fails with InvalidParameterException and its exact
    message, and after AdminDisableProviderForUser the same link to the second user succeeds."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx, UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})
    dest_a = _create_user(ctx, pool_id, _unique(ctx, "user-a"), _PASSWORD)
    dest_b = _create_user(ctx, pool_id, _unique(ctx, "user-b"), _PASSWORD)

    provider_name = _provider_name(ctx)
    idp.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=provider_name,
        ProviderType="OIDC",
        ProviderDetails={
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "attributes_request_method": "GET",
            "oidc_issuer": _cognito_issuer(ctx),
            "authorize_scopes": "openid email",
        },
    )
    ctx.on_cleanup(lambda: idp.delete_identity_provider(UserPoolId=pool_id, ProviderName=provider_name))

    external_sub = _unique(ctx, "ext-sub")
    source_user = {
        "ProviderName": provider_name,
        "ProviderAttributeName": "Cognito_Subject",
        "ProviderAttributeValue": external_sub,
    }

    # Success path: link the federated identity to destination user A.
    idp.admin_link_provider_for_user(
        UserPoolId=pool_id,
        DestinationUser={"ProviderName": "Cognito", "ProviderAttributeValue": dest_a},
        SourceUser=source_user,
    )
    identities = _get_identities(idp, pool_id, dest_a)
    assert any(
        i.get("providerName") == provider_name and i.get("userId") == external_sub for i in identities
    ), identities

    # Negative: the very same source identity cannot also be linked to a different
    # destination user -- it's already claimed. Real AWS rejects this with
    # InvalidParameterException rather than AliasExistsException.
    code = _client_error(
        lambda: idp.admin_link_provider_for_user(
            UserPoolId=pool_id,
            DestinationUser={"ProviderName": "Cognito", "ProviderAttributeValue": dest_b},
            SourceUser=source_user,
        )
    )
    assert code.get("Code") == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert code.get("Message") == "Invalid SourceUser: Cognito users with a username/password may not be passed in as a SourceUser, only as a DestinationUser", code.get("Message")

    # Effect-absent: the rejected call must not have created a link on destination B.
    dest_b_identities = _get_identities(idp, pool_id, dest_b)
    assert not any(i.get("userId") == external_sub for i in dest_b_identities), dest_b_identities

    # Restore: detach the first link, freeing the source identity.
    idp.admin_disable_provider_for_user(UserPoolId=pool_id, User=source_user)
    dest_a_identities = _get_identities(idp, pool_id, dest_a)
    assert not any(i.get("userId") == external_sub for i in dest_a_identities), dest_a_identities

    # The identical call that was rejected above must now succeed against the freed source.
    idp.admin_link_provider_for_user(
        UserPoolId=pool_id,
        DestinationUser={"ProviderName": "Cognito", "ProviderAttributeValue": dest_b},
        SourceUser=source_user,
    )
    dest_b_identities = _get_identities(idp, pool_id, dest_b)
    assert any(
        i.get("providerName") == provider_name and i.get("userId") == external_sub for i in dest_b_identities
    ), dest_b_identities


def _unique(ctx, kind: str) -> str:
    return ctx.unique_name(f"sim2real-behav-{kind}-")


def _provider_name(ctx) -> str:
    raw = ctx.unique_name("idp")
    short = "".join(ch for ch in raw if ch.isalnum())[-16:]
    return f"TestOIDC{short}"


def _create_user_pool(ctx, **kwargs):
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(PoolName=_unique(ctx, "pool"), **kwargs)["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_user(ctx, pool_id, username, password=None, permanent=True, attrs=None):
    idp = ctx.client("cognito-idp")
    kwargs = {
        "UserPoolId": pool_id,
        "Username": username,
        "MessageAction": "SUPPRESS",
        "UserAttributes": attrs
        or [
            {"Name": "email", "Value": f"{username}@example.com"},
            {"Name": "email_verified", "Value": "true"},
        ],
    }
    if password:
        kwargs["TemporaryPassword"] = password
    idp.admin_create_user(**kwargs)
    ctx.on_cleanup(lambda: _safe_delete_user(ctx, pool_id, username))
    if password and permanent:
        idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    return username


def _safe_delete_user(ctx, pool_id, username) -> None:
    idp = ctx.client("cognito-idp")
    try:
        idp.admin_delete_user(UserPoolId=pool_id, Username=username)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "UserNotFoundException",
        ):
            raise


def _get_identities(idp, pool_id, username):
    resp = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    for attr in resp["UserAttributes"]:
        if attr["Name"] == "identities":
            return json.loads(attr["Value"])
    return []


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _cognito_issuer(ctx) -> str:
    """The OIDC issuer of a second Cognito user pool this check creates: its pool id under
    the endpoint that serves it.

    The check owns the issuer, so no third-party identity provider is named or contacted; Cognito
    reads the pool's OIDC discovery document like any issuer's.
    """
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-oidc-issuer-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return ctx.service_url(f"https://cognito-idp.{ctx.region}.amazonaws.com") + f"/{pool_id}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
