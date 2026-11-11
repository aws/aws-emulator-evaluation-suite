"""alias-exists-on-provider-link."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alias-exists-on-provider-link"
GROUP = 'user-lifecycle'
SERVICES = ['cognito-idp']

_LENIENT_PASSWORD_POLICY = {
    "PasswordPolicy": {
        "MinimumLength": 8,
        "RequireUppercase": False,
        "RequireLowercase": False,
        "RequireNumbers": False,
        "RequireSymbols": False,
    }
}
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
PASSWORD = "Str0ngPassw0rd!"


def _err(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises AssertionError, so an emulator accepting what AWS refuses never reads as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _identities(c, pool_id, username):
    attrs = c.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]
    raw = next((a["Value"] for a in attrs if a["Name"] == "identities"), None)
    return json.loads(raw) if raw else []


def _new_pool(ctx, c, **kwargs):
    kwargs.setdefault("Policies", _LENIENT_PASSWORD_POLICY)
    kwargs.setdefault("UserPoolTags", _POOL_TAGS)
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), **kwargs
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _new_social_idp(ctx, c, pool_id, provider_name="Facebook", provider_type="Facebook"):
    """CreateIdentityProvider using a built-in social provider type (no real credentials or network
    validation at creation time -- Cognito only stores the client_id/secret). Track for cleanup."""
    c.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=provider_name,
        ProviderType=provider_type,
        ProviderDetails={
            "client_id": "sim2real-fake-app-id",
            "client_secret": "sim2real-fake-app-secret",
            "authorize_scopes": "public_profile,email",
        },
        AttributeMapping={"email": "email"},
    )
    ctx.on_cleanup(
        lambda: c.delete_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)
    )
    return provider_name


def _new_confirmed_user(ctx, c, pool_id, password=PASSWORD, **extra_attrs):
    username = ctx.unique_name("sim2real-behav-cip-user-")
    attrs = [{"Name": "email", "Value": f"{username}@example.com"}]
    attrs.extend({"Name": k, "Value": v} for k, v in extra_attrs.items())
    c.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="Temp0rar1Pass!",
        MessageAction="SUPPRESS",
        UserAttributes=attrs,
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    return username, password


def _link(c, pool_id, dest_username, source_user):
    c.admin_link_provider_for_user(
        UserPoolId=pool_id,
        DestinationUser={"ProviderName": "Cognito", "ProviderAttributeValue": dest_username},
        SourceUser=source_user,
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Linking an external identity already linked to one user to a second user is refused with
    InvalidParameterException, and after AdminDisableProviderForUser with AliasExistsException, each
    with the exact message; the second user stays unlinked."""
    c = ctx.client("cognito-idp")
    pool_id = _new_pool(ctx, c)
    _new_social_idp(ctx, c, pool_id, provider_name="Facebook", provider_type="Facebook")
    dest_a, _ = _new_confirmed_user(ctx, c, pool_id)
    dest_b, _ = _new_confirmed_user(ctx, c, pool_id)

    external_id = ctx.unique_name("sim2real-behav-fb-ext-")
    source_user = {
        "ProviderName": "Facebook",
        "ProviderAttributeName": "Cognito_Subject",
        "ProviderAttributeValue": external_id,
    }

    # Positive control: linking the external identity to dest_a succeeds and is visible on dest_a.
    _link(c, pool_id, dest_a, source_user)
    assert any(i.get("providerName") == "Facebook" and i.get("userId") == external_id
               for i in _identities(c, pool_id, dest_a)), (
        f"expected the Facebook link visible in dest_a's identities, got {_identities(c, pool_id, dest_a)}"
    )

    # Break: the SAME external identity can't also be linked to dest_b -- it's already claimed.
    code, code_msg = _err(lambda: _link(c, pool_id, dest_b, source_user))
    assert code == "InvalidParameterException", (
        f"expected linking an already-linked external identity to a second destination user to be "
        f"rejected (InvalidParameterException), got {code}"
    )
    assert code_msg == 'Invalid SourceUser: Cognito users with a username/password may not be passed in as a SourceUser, only as a DestinationUser', f"expected the exact {code} message, got {code_msg!r}"

    # Effect-absent: the rejected attempt must not have left any trace on dest_b.
    assert _identities(c, pool_id, dest_b) == [], (
        f"expected the rejected link attempt to leave dest_b unlinked, got {_identities(c, pool_id, dest_b)}"
    )

    c.admin_disable_provider_for_user(
        UserPoolId=pool_id,
        User={
            "ProviderName": "Cognito",
            "ProviderAttributeName": "Cognito_Subject",
            "ProviderAttributeValue": dest_a,
        },
    )

    # AdminDisableProviderForUser detaches the federated link from dest_a's sign-in surface without
    # deleting the native user record itself.
    still_exists = c.admin_get_user(UserPoolId=pool_id, Username=dest_a)
    assert still_exists["Username"] == dest_a, (
        f"AdminDisableProviderForUser must not delete the destination user's native account, "
        f"got {still_exists}"
    )

    # Disabling dest_a's link does NOT release the alias claim: the identical link attempt
    # against dest_b is rejected again, now as AliasExistsException, even though the link it's
    # guarding is no longer active on dest_a's sign-in surface.
    code_after_disable, code_after_disable_msg = _err(lambda: _link(c, pool_id, dest_b, source_user))
    assert code_after_disable == "AliasExistsException", (
        f"expected the external identity to remain claimed after AdminDisableProviderForUser "
        f"(AliasExistsException), got {code_after_disable}"
    )
    assert code_after_disable_msg == 'SourceUser with the specified attribute value is already linked to another user', f"expected the exact {code_after_disable} message, got {code_after_disable_msg!r}"

    # Terminal, independent read at the destination: dest_b never received the link, before or
    # after dest_a's provider was disabled.
    linked_on_b = _identities(c, pool_id, dest_b)
    assert linked_on_b == [], (
        f"expected dest_b to remain unlinked throughout, got {linked_on_b}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
