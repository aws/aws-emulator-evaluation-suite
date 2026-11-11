"""get-identity-pool-roles-rules-evaluated-in-declared-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-identity-pool-roles-rules-evaluated-in-declared-order"
GROUP = "ordering"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c7", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """GetIdentityPoolRoles returns the Rules in declared order, and when several match a token Cognito
    applies the FIRST: the role GetCredentialsForIdentity assumes follows the first rule, and flips
    when the rules are reordered."""
    cid = ctx.client("cognito-identity")
    up = _create_user_pool_and_id_token(ctx)
    provider_name = up["provider_name"]
    client_id = up["client_id"]

    pool = cid.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=False,
        CognitoIdentityProviders=[
            {"ProviderName": provider_name, "ClientId": client_id, "ServerSideTokenCheck": False}
        ],
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: cid.delete_identity_pool(IdentityPoolId=pool_id))

    role_a_name, role_a_arn = _create_trusting_role(ctx, pool_id, "authenticated")
    role_b_name, role_b_arn = _create_trusting_role(ctx, pool_id, "authenticated")

    role_mapping_key = f"{provider_name}:{client_id}"
    # Both rules independently match every login token issued by this user pool client:
    # "aud" always equals client_id, and "token_use" is always "id" for an ID token. With
    # both conditions permanently true, only declared array order can decide the winner.
    rule_aud = {"Claim": "aud", "MatchType": "Equals", "Value": client_id}
    rule_token_use = {"Claim": "token_use", "MatchType": "Equals", "Value": "id"}

    def set_rules(first_role_arn, second_role_arn):
        cid.set_identity_pool_roles(
            IdentityPoolId=pool_id,
            Roles={"authenticated": role_a_arn},
            RoleMappings={
                role_mapping_key: {
                    "Type": "Rules",
                    "AmbiguousRoleResolution": "Deny",
                    "RulesConfiguration": {
                        "Rules": [
                            {**rule_aud, "RoleARN": first_role_arn},
                            {**rule_token_use, "RoleARN": second_role_arn},
                        ]
                    },
                }
            },
        )
        rules = cid.get_identity_pool_roles(IdentityPoolId=pool_id)["RoleMappings"][role_mapping_key][
            "RulesConfiguration"
        ]["Rules"]
        assert [r["RoleARN"] for r in rules] == [first_role_arn, second_role_arn], (
            f"expected GetIdentityPoolRoles to return the rules in declared order, got {rules!r}"
        )

    logins = {provider_name: up["id_token"]}
    identity_id = cid.get_id(IdentityPoolId=pool_id, Logins=logins)["IdentityId"]
    ctx.on_cleanup(lambda: cid.delete_identities(IdentityIdsToDelete=[identity_id]))

    set_rules(role_a_arn, role_b_arn)
    creds1 = _get_credentials_with_retry(ctx, identity_id, logins=logins)["Credentials"]
    arn1 = _assumed_role_arn(ctx, creds1)
    assert f"assumed-role/{role_a_name}/" in arn1, f"expected role A (first rule) to win, got {arn1}"

    set_rules(role_b_arn, role_a_arn)
    creds2 = _get_credentials_with_retry(ctx, identity_id, logins=logins, timeout_s=20.0)["Credentials"]
    arn2 = _assumed_role_arn(ctx, creds2)
    assert f"assumed-role/{role_b_name}/" in arn2, (
        f"expected role B to win after it became the first declared rule, got {arn2}"
    )


def _create_user_pool_and_id_token(ctx):
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-userpool-"),
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    username = ctx.unique_name("sim2real-behav-user-")
    password = "Sim2Real-Behav-Pw1!"
    idp.admin_create_user(
        UserPoolId=pool_id, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS"
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    id_token = auth["AuthenticationResult"]["IdToken"]
    provider_name = f"cognito-idp.{ctx.region}.amazonaws.com/{pool_id}"
    return {
        "user_pool_id": pool_id,
        "client_id": client_id,
        "id_token": id_token,
        "provider_name": provider_name,
    }


def _create_trusting_role(ctx, pool_id: str, amr: str, max_session_duration: int = 3600):
    import json

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": amr},
                },
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        MaxSessionDuration=max_session_duration,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_name, role["Arn"]


def _get_credentials_with_retry(
    ctx, identity_id, logins=None, custom_role_arn=None, timeout_s=45.0, interval_s=3.0
):
    import time

    from botocore.exceptions import ClientError

    cid = ctx.client("cognito-identity")
    kwargs = {"IdentityId": identity_id}
    if logins:
        kwargs["Logins"] = logins
    if custom_role_arn:
        kwargs["CustomRoleArn"] = custom_role_arn
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return cid.get_credentials_for_identity(**kwargs)
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"GetCredentialsForIdentity never succeeded within {timeout_s}s: {last_exc}")


def _assumed_role_arn(ctx, credentials):
    assumed = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": credentials["AccessKeyId"],
            "aws_secret_access_key": credentials["SecretKey"],
            "aws_session_token": credentials["SessionToken"],
        },
    )
    return assumed.get_caller_identity()["Arn"]

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
