"""alias-exists-on-challenge-response."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "alias-exists-on-challenge-response"
GROUP = 'auth-state-machine'
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
_AUTH_FLOWS = [
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
]


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


def _create_user(ctx, c, pool_id, username, temp_password):
    c.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=temp_password,
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))


def _admin_initiate_auth_raw(c, pool_id, client_id, username, password):
    return c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """AdminRespondToAuthChallenge and RespondToAuthChallenge answering NEW_PASSWORD_REQUIRED with
    an email that another user holds as a verified alias both complete sign-in and store that email
    unverified."""
    c = ctx.client("cognito-idp")
    pool_id = _new_pool(
        ctx,
        c,
        AliasAttributes=["email"],
        AutoVerifiedAttributes=["email"],
        Schema=[{"Name": "email", "AttributeDataType": "String", "Required": True, "Mutable": True}],
    )
    client_id = _new_client(ctx, c, pool_id, ExplicitAuthFlows=list(_AUTH_FLOWS))["ClientId"]

    username_a, _ = _new_confirmed_user(ctx, c, pool_id, email_verified="true")
    claimed_email = f"{username_a}@example.com"
    temp_password = "Temp0rar1Pass!"

    # -- AdminRespondToAuthChallenge path --
    username_admin = ctx.unique_name("sim2real-behav-cip-chal-admin-")
    _create_user(ctx, c, pool_id, username_admin, temp_password)

    challenge = _admin_initiate_auth_raw(c, pool_id, client_id, username_admin, temp_password)
    assert challenge.get("ChallengeName") == "NEW_PASSWORD_REQUIRED", challenge.get("ChallengeName")

    completed1 = c.admin_respond_to_auth_challenge(
        UserPoolId=pool_id,
        ClientId=client_id,
        ChallengeName="NEW_PASSWORD_REQUIRED",
        Session=challenge["Session"],
        ChallengeResponses={
            "USERNAME": username_admin,
            "NEW_PASSWORD": "BrandNewChallenge0!",
            "userAttributes.email": claimed_email,
        },
    )
    assert "AuthenticationResult" in completed1, (
        f"expected a completed sign-in supplying a required attribute during NEW_PASSWORD_REQUIRED, "
        f"even though its value collides with another user's verified alias, got {completed1}"
    )
    admin_attrs = {
        a["Name"]: a["Value"]
        for a in c.admin_get_user(UserPoolId=pool_id, Username=username_admin)["UserAttributes"]
    }
    assert admin_attrs.get("email") == claimed_email, admin_attrs.get("email")
    assert admin_attrs.get("email_verified") in (None, "false"), (
        f"the colliding email supplied via a challenge response must never be silently marked "
        f"verified, got email_verified={admin_attrs.get('email_verified')!r}"
    )

    # -- RespondToAuthChallenge (self-service) path --
    username_self = ctx.unique_name("sim2real-behav-cip-chal-self-")
    _create_user(ctx, c, pool_id, username_self, temp_password)

    challenge2 = c.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username_self, "PASSWORD": temp_password},
    )
    assert challenge2.get("ChallengeName") == "NEW_PASSWORD_REQUIRED", challenge2.get("ChallengeName")

    completed2 = c.respond_to_auth_challenge(
        ClientId=client_id,
        ChallengeName="NEW_PASSWORD_REQUIRED",
        Session=challenge2["Session"],
        ChallengeResponses={
            "USERNAME": username_self,
            "NEW_PASSWORD": "AnotherNewChallenge0!",
            "userAttributes.email": claimed_email,
        },
    )
    assert "AuthenticationResult" in completed2, (
        f"expected a completed self-service sign-in despite the colliding email attribute, "
        f"got {completed2}"
    )
    self_attrs = {
        a["Name"]: a["Value"]
        for a in c.admin_get_user(UserPoolId=pool_id, Username=username_self)["UserAttributes"]
    }
    assert self_attrs.get("email") == claimed_email, self_attrs.get("email")
    assert self_attrs.get("email_verified") in (None, "false"), (
        f"the colliding email supplied via a self-service challenge response must never be silently "
        f"marked verified, got email_verified={self_attrs.get('email_verified')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
