"""server-side-sts-role-session-tags-enforced-in-trust-policy."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-sts-role-session-tags-enforced-in-trust-policy"
GROUP = "server-side"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A role trust policy conditioned on aws:RequestTag gates GetCredentialsForIdentity: an
    identity whose mapped principal tag satisfies it gets credentials, one that does not is
    rejected at assumption time."""
    region = ctx.region
    cidp = ctx.client("cognito-idp")
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    pool_id, client_id = _create_user_pool_with_dept_attr(ctx, cidp)
    provider_name = f"cognito-idp.{region}.amazonaws.com/{pool_id}"

    identity_pool = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=False,
        CognitoIdentityProviders=[
            {"ProviderName": provider_name, "ClientId": client_id, "ServerSideTokenCheck": False}
        ],
        IdentityPoolTags={"sim2real": CHECK},
    )
    identity_pool_id = identity_pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=identity_pool_id))

    ci.set_principal_tag_attribute_map(
        IdentityPoolId=identity_pool_id,
        IdentityProviderName=provider_name,
        UseDefaults=False,
        PrincipalTags={"Department": "custom:dept"},
    )

    # Trust policy only allows the AssumeRoleWithWebIdentity+TagSession request to succeed when
    # the *requested* session tag is Department=eng.
    role_arn, _role_name = _create_cognito_role(
        ctx, iam, identity_pool_id, extra_conditions={"aws:RequestTag/Department": "eng"}
    )
    ci.set_identity_pool_roles(IdentityPoolId=identity_pool_id, Roles={"authenticated": role_arn})

    eng_token = _create_confirmed_user_id_token(ctx, cidp, pool_id, client_id, dept="eng")
    fin_token = _create_confirmed_user_id_token(ctx, cidp, pool_id, client_id, dept="finance")

    eng_identity_id = ci.get_id(IdentityPoolId=identity_pool_id, Logins={provider_name: eng_token})["IdentityId"]
    fin_identity_id = ci.get_id(IdentityPoolId=identity_pool_id, Logins={provider_name: fin_token})["IdentityId"]

    # Confirm the trust policy/role has fully propagated before treating a later denial as real.
    matching_creds = _retry_get_credentials(ctx, eng_identity_id, logins={provider_name: eng_token})
    assert matching_creds["Credentials"]["AccessKeyId"], "matching-tag identity failed to obtain credentials"

    code, message = _error(
        lambda: ci.get_credentials_for_identity(
            IdentityId=fin_identity_id,
            Logins={provider_name: fin_token},
        )
    )
    assert code == "InvalidIdentityPoolConfigurationException", (
        f"mismatched Department tag was not rejected by the trust policy at assumption time: got {code!r}"
    )
    assert message == "Invalid identity pool configuration. Check assigned IAM roles for this pool.", (
        f"expected the exact refusal message AWS returns, got {message!r}"
    )




def _create_user_pool_with_dept_attr(ctx, cidp):
    pool = cidp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-up-"),
        Schema=[{"Name": "dept", "AttributeDataType": "String", "Mutable": True}],
        UserPoolTags={"sim2real": CHECK},
    )
    pool_id = pool["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cidp.delete_user_pool(UserPoolId=pool_id))
    client = cidp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-upc-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )
    client_id = client["UserPoolClient"]["ClientId"]
    return pool_id, client_id


def _create_confirmed_user_id_token(ctx, cidp, pool_id, client_id, dept):
    username = ctx.unique_name("sim2real-behav-user-")
    password = "Sim2Real-Pass-1!"
    cidp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "custom:dept", "Value": dept}],
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
    )
    cidp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    auth = cidp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return auth["AuthenticationResult"]["IdToken"]


def _error(fn):
    """Call fn(); return (Code, Message) of the ClientError it raises, and fail if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_cognito_role(ctx, iam, pool_id, extra_conditions=None):
    name = ctx.unique_name("sim2real-behav-role-")
    string_equals = {"cognito-identity.amazonaws.com:aud": pool_id}
    if extra_conditions:
        string_equals.update(extra_conditions)
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": ["sts:AssumeRoleWithWebIdentity", "sts:TagSession"],
                "Condition": {
                    "StringEquals": string_equals,
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "authenticated"},
                },
            }
        ],
    }
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return role_arn, name


def _retry_get_credentials(ctx, identity_id, logins=None, timeout_s=90.0, interval_s=5.0):
    ci = ctx.client("cognito-identity")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            kwargs = {"IdentityId": identity_id}
            if logins:
                kwargs["Logins"] = logins
            return ci.get_credentials_for_identity(**kwargs)
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"GetCredentialsForIdentity never succeeded within {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
