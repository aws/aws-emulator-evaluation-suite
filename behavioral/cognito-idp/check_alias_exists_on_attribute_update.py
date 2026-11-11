"""alias-exists-on-attribute-update."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "alias-exists-on-attribute-update"
GROUP = 'user-attributes'
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


def _new_pool(ctx, c, **kwargs):
    kwargs.setdefault("Policies", _LENIENT_PASSWORD_POLICY)
    kwargs.setdefault("UserPoolTags", _POOL_TAGS)
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), **kwargs
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _new_client(ctx, c, pool_id, **kwargs):
    kwargs.setdefault("GenerateSecret", False)
    client = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), **kwargs
    )["UserPoolClient"]
    ctx.on_cleanup(
        lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client["ClientId"])
    )
    return client


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


def _admin_login(c, pool_id, client_id, username, password):
    resp = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert "AuthenticationResult" in resp, f"expected AuthenticationResult, got a challenge: {resp}"
    return resp["AuthenticationResult"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateUserAttributes and AdminUpdateUserAttributes accept an email another user holds as a
    verified alias, store it on the writer, and leave the previous holder's copy unverified."""
    c = ctx.client("cognito-idp")
    pool_id = _new_pool(ctx, c, AliasAttributes=["email"])
    client_id = _new_client(
        ctx, c, pool_id, ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
    )["ClientId"]

    username_a, _ = _new_confirmed_user(ctx, c, pool_id, email_verified="true")
    claimed_email = f"{username_a}@example.com"

    username_b, password_b = _new_confirmed_user(ctx, c, pool_id)
    auth = _admin_login(c, pool_id, client_id, username_b, password_b)
    access_token = auth["AccessToken"]

    # No verification required before updating email, so the raw value change applies immediately
    # -- tolerated even though it duplicates another user's verified email, because B's copy is
    # never marked verified.
    c.update_user_attributes(
        AccessToken=access_token, UserAttributes=[{"Name": "email", "Value": claimed_email}]
    )
    got1 = c.get_user(AccessToken=access_token)
    attrs1 = {a["Name"]: a["Value"] for a in got1["UserAttributes"]}
    assert attrs1.get("email") == claimed_email, (
        f"expected the unverified email value change to apply immediately, got {attrs1.get('email')!r}"
    )
    assert attrs1.get("email_verified") in (None, "false"), (
        f"the self-service update must never silently mark the duplicated email verified, got "
        f"email_verified={attrs1.get('email_verified')!r}"
    )

    # Even promoting that SAME duplicated value to verified via the admin skip-verification shortcut
    # is accepted -- AdminUpdateUserAttributes does not cross-check AliasAttributes exclusivity.
    c.admin_update_user_attributes(
        UserPoolId=pool_id,
        Username=username_b,
        UserAttributes=[
            {"Name": "email", "Value": claimed_email},
            {"Name": "email_verified", "Value": "true"},
        ],
    )
    got2 = c.admin_get_user(UserPoolId=pool_id, Username=username_b)
    attrs2 = {a["Name"]: a["Value"] for a in got2["UserAttributes"]}
    assert attrs2.get("email") == claimed_email, (
        f"expected AdminUpdateUserAttributes to apply the duplicated email value "
        f"{claimed_email!r} to B, got {attrs2.get('email')!r}"
    )
    assert attrs2.get("email_verified") == "true", (
        f"expected AdminUpdateUserAttributes's email_verified=true skip to apply even for a value "
        f"duplicated from another user's verified alias, got {attrs2.get('email_verified')!r}"
    )
    # Rather than rejecting B's write, Cognito silently DEMOTES A's now-shared email out of verified
    # status to preserve uniqueness of the verified alias -- B's write wins, A's copy is unverified.
    a_attrs = {
        a["Name"]: a["Value"]
        for a in c.admin_get_user(UserPoolId=pool_id, Username=username_a)["UserAttributes"]
    }
    assert a_attrs.get("email") == claimed_email, (
        f"expected A's email to remain the now-shared value {claimed_email!r} even after "
        f"demotion, got {a_attrs.get('email')!r}"
    )
    assert a_attrs.get("email_verified") in (None, "false"), (
        f"expected A's now-shared email to be demoted out of verified status once B claimed it, "
        f"got email_verified={a_attrs.get('email_verified')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
