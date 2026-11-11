"""deploy-cognito-identity-3-cfn-principal-tag-without-tag-session-rejected."""
from __future__ import annotations

import json
import re
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cognito-identity-3-cfn-principal-tag-without-tag-session-rejected"
GROUP = "deploy-cfn-principal-tag"
SERVICES = ["cognito-identity"]

# A pool with a PrincipalTags mapping refuses to vend
# through a role whose trust grants sts:AssumeRoleWithWebIdentity but not sts:TagSession, with
# InvalidIdentityPoolConfigurationException. That is also the code a not-yet-propagated role
# returns, which is why the unmapped pool's vend through an identical role is taken first as the
# barrier, and why the refusal is required to hold across several attempts after it.
REFUSED_CODE = "InvalidIdentityPoolConfigurationException"
REFUSED_MESSAGE = "Invalid identity pool configuration. Check assigned IAM roles for this pool."
_TRANSIENT_VEND = (
    "InvalidIdentityPoolConfigurationException", "AccessDenied", "AccessDeniedException",
    "NotAuthorizedException", "ThrottlingException", "TooManyRequestsException",
)
_TERMINAL_OK = {"CREATE_COMPLETE", "UPDATE_COMPLETE"}


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CFN-deployed IdentityPoolPrincipalTag makes the attached role need sts:TagSession: without
    it the mapped pool refuses to vend while an identical unmapped pool vends, and adding
    sts:TagSession by an in-place stack update repairs the vend for the same identity.
    """
    cfn = ctx.client("cloudformation")
    ci = ctx.client("cognito-identity")
    idp = ctx.client("cognito-idp")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    stack_name = ctx.unique_name("sim2real-cfn-cip-tagsess-")
    names = {
        "user_pool": ctx.unique_name("sim2real-cip-tagsess-up-"),
        "mapped_pool": ctx.unique_name("sim2real_cip_mapped_").replace("-", "_"),
        "unmapped_pool": ctx.unique_name("sim2real_cip_unmapped_").replace("-", "_"),
        "mapped_role": ctx.unique_name("sim2real-cip-mapped-role-")[:64],
        "unmapped_role": ctx.unique_name("sim2real-cip-unmapped-role-")[:64],
    }

    cfn.create_stack(StackName=stack_name, TemplateBody=_template(names, tag_session=False),
                     Capabilities=["CAPABILITY_NAMED_IAM"],
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    _wait_stack(ctx, cfn, stack_name, _TERMINAL_OK)
    out = _stack_outputs(cfn, stack_name)
    user_pool_id, client_id, provider = out["UserPoolId"], out["ClientId"], out["ProviderName"]
    mapped_pool, unmapped_pool = out["MappedPoolId"], out["UnmappedPoolId"]

    stored = ci.get_principal_tag_attribute_map(IdentityPoolId=mapped_pool,
                                                IdentityProviderName=provider)
    assert stored.get("PrincipalTags") == {"tenant": "custom:tenant"}, (
        f"the mapped pool's map reads {stored.get('PrincipalTags')!r}"
    )

    username = ctx.unique_name("sim2real-cip-tagsess-user-")
    password = "Sim2Real!" + uuid.uuid4().hex[:12]
    idp.admin_create_user(UserPoolId=user_pool_id, Username=username, MessageAction="SUPPRESS",
                          UserAttributes=[{"Name": "custom:tenant", "Value": "tenant-a"}])
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=user_pool_id, Username=username))
    idp.admin_set_user_password(UserPoolId=user_pool_id, Username=username, Password=password,
                                Permanent=True)

    def _logins():
        token = idp.admin_initiate_auth(
            UserPoolId=user_pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )["AuthenticationResult"]["IdToken"]
        return {provider: token}

    logins = _logins()
    mapped_id = ci.get_id(IdentityPoolId=mapped_pool, Logins=logins)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[mapped_id]))
    unmapped_id = ci.get_id(IdentityPoolId=unmapped_pool, Logins=logins)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[unmapped_id]))

    # ---- positive control / barrier: the unmapped pool vends through a TagSession-less role,
    # proving the roles have propagated, so the refusal below is not IAM eventual consistency
    control = _vend_until_ok(ctx, ci, unmapped_id, logins)
    _assert_assumed(ctx, control, account_id, names["unmapped_role"], "unmapped pool")

    # ---- the one difference: the mapped pool, same login, same trust shape -> refused
    for attempt in range(3):
        code, message, creds = _vend_once(ci, mapped_id, logins)
        assert creds is None, (
            f"attempt {attempt}: the mapped pool vended credentials through a role that does not "
            f"trust sts:TagSession: {creds.get('AccessKeyId')!r}"
        )
        assert code == REFUSED_CODE, (
            f"attempt {attempt}: expected {REFUSED_CODE!r} from the mapped pool, got {code!r}"
        )
        assert message == REFUSED_MESSAGE, (message, REFUSED_MESSAGE)
        time.sleep(1.0)

    # ---- repair exactly that thing in place, and the same identity now vends
    cfn.update_stack(StackName=stack_name, TemplateBody=_template(names, tag_session=True),
                     Capabilities=["CAPABILITY_NAMED_IAM"])
    _wait_stack(ctx, cfn, stack_name, _TERMINAL_OK)
    assert _stack_outputs(cfn, stack_name)["MappedPoolId"] == mapped_pool, (
        "a trust-policy-only update replaced the identity pool"
    )
    repaired = _vend_until_ok(ctx, ci, mapped_id, _logins(), timeout_s=180.0)
    _assert_assumed(ctx, repaired, account_id, names["mapped_role"], "mapped pool after repair")


def _trust(pool_logical_id: str, tag_session: bool) -> dict:
    actions = ["sts:AssumeRoleWithWebIdentity"] + (["sts:TagSession"] if tag_session else [])
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": actions,
            "Condition": {
                "StringEquals": {"cognito-identity.amazonaws.com:aud": {"Ref": pool_logical_id}},
                "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "authenticated"},
            },
        }],
    }


def _pool(name: str) -> dict:
    return {
        "Type": "AWS::Cognito::IdentityPool",
        "Properties": {
            "IdentityPoolName": name,
            "AllowUnauthenticatedIdentities": False,
            "CognitoIdentityProviders": [{
                "ProviderName": {"Fn::GetAtt": ["UserPool", "ProviderName"]},
                "ClientId": {"Ref": "UserPoolClient"},
                "ServerSideTokenCheck": False,
            }],
            "IdentityPoolTags": [{"Key": "sim2real", "Value": CHECK}],
        },
    }


def _role(name: str, trust: dict) -> dict:
    return {
        "Type": "AWS::IAM::Role",
        "Properties": {
            "RoleName": name,
            "Description": "sim2real deploy probe role for Cognito Identity TagSession",
            "Tags": [{"Key": "sim2real", "Value": CHECK}],
            "AssumeRolePolicyDocument": trust,
        },
    }


def _template(names: dict, tag_session: bool) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "UserPool": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {
                    "UserPoolName": names["user_pool"],
                    "Schema": [{
                        "Name": "tenant", "AttributeDataType": "String", "Mutable": True,
                        "Required": False,
                        "StringAttributeConstraints": {"MinLength": "1", "MaxLength": "64"},
                    }],
                    "UserPoolTags": {"sim2real": CHECK},
                },
            },
            "UserPoolClient": {
                "Type": "AWS::Cognito::UserPoolClient",
                "Properties": {
                    "UserPoolId": {"Ref": "UserPool"},
                    "ClientName": "sim2real-cip-tagsess-client",
                    "GenerateSecret": False,
                    "ExplicitAuthFlows": ["ALLOW_ADMIN_USER_PASSWORD_AUTH",
                                          "ALLOW_REFRESH_TOKEN_AUTH"],
                },
            },
            "MappedPool": _pool(names["mapped_pool"]),
            "UnmappedPool": _pool(names["unmapped_pool"]),
            "PrincipalTag": {
                "Type": "AWS::Cognito::IdentityPoolPrincipalTag",
                "Properties": {
                    "IdentityPoolId": {"Ref": "MappedPool"},
                    "IdentityProviderName": {"Fn::GetAtt": ["UserPool", "ProviderName"]},
                    "PrincipalTags": {"tenant": "custom:tenant"},
                    "UseDefaults": False,
                },
            },
            "MappedRole": _role(names["mapped_role"], _trust("MappedPool", tag_session)),
            "UnmappedRole": _role(names["unmapped_role"], _trust("UnmappedPool", False)),
            "MappedAttachment": {
                "Type": "AWS::Cognito::IdentityPoolRoleAttachment",
                "Properties": {
                    "IdentityPoolId": {"Ref": "MappedPool"},
                    "Roles": {"authenticated": {"Fn::GetAtt": ["MappedRole", "Arn"]}},
                },
            },
            "UnmappedAttachment": {
                "Type": "AWS::Cognito::IdentityPoolRoleAttachment",
                "Properties": {
                    "IdentityPoolId": {"Ref": "UnmappedPool"},
                    "Roles": {"authenticated": {"Fn::GetAtt": ["UnmappedRole", "Arn"]}},
                },
            },
        },
        "Outputs": {
            "UserPoolId": {"Value": {"Ref": "UserPool"}},
            "ClientId": {"Value": {"Ref": "UserPoolClient"}},
            "ProviderName": {"Value": {"Fn::GetAtt": ["UserPool", "ProviderName"]}},
            "MappedPoolId": {"Value": {"Ref": "MappedPool"}},
            "UnmappedPoolId": {"Value": {"Ref": "UnmappedPool"}},
        },
    })


def _stack_failure_reasons(cfn, stack_name: str) -> list:
    reasons = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        for ev in page["StackEvents"]:
            if ev.get("ResourceStatus", "").endswith("_FAILED"):
                reasons.append((ev["LogicalResourceId"], ev.get("ResourceStatusReason")))
        if len(reasons) >= 5:
            break
    return reasons[:5]


def _wait_stack(ctx, cfn, stack_name: str, ok: set, timeout_s: float = 900.0) -> str:
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.time() + timeout_s
    status = None
    while time.time() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in ok:
            return status
        if not status.endswith("_IN_PROGRESS"):
            raise AssertionError(
                f"stack {stack_name} reached {status!r}: {_stack_failure_reasons(cfn, stack_name)!r}"
            )
        time.sleep(1.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"stack {stack_name} reaching {sorted(ok)!r}: the run budget ended first; not graded")
    raise AssertionError(f"stack {stack_name} still {status!r} after {timeout_s}s")


def _stack_outputs(cfn, stack_name: str) -> dict:
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    deadline = time.time() + 900
    while time.time() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise RuntimeError(f"stack {stack_name} DELETE_FAILED: "
                               f"{_stack_failure_reasons(cfn, stack_name)!r}")
        time.sleep(2)
    raise RuntimeError(f"stack {stack_name} not deleted within 900s")


def _vend_once(ci, identity_id, logins):
    """(None, None, credentials) on success; (error code, message, None) if refused."""
    try:
        return None, None, ci.get_credentials_for_identity(IdentityId=identity_id,
                                                           Logins=logins)["Credentials"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message"), None


def _vend_until_ok(ctx, ci, identity_id, logins, timeout_s=120.0):
    """Retry only the transient role-propagation refusals until credentials are vended."""
    deadline = time.time() + _budget_s(ctx, timeout_s)
    while True:
        code, message, creds = _vend_once(ci, identity_id, logins)
        if creds is not None:
            return creds
        if code in _TRANSIENT_VEND and time.time() < deadline:
            time.sleep(1.0)
            continue
        if code in _TRANSIENT_VEND and _budget_spent(ctx):
            raise TimeoutError(f"GetCredentialsForIdentity vending for {identity_id!r}: the run budget ended first; not graded")
        raise AssertionError(f"GetCredentialsForIdentity never vended for {identity_id!r}: "
                             f"last code {code!r}: {message!r}")


def _assert_assumed(ctx, creds, account_id, role_name, why):
    sts = ctx.client(
        "sts",
        config=Config(retries={"max_attempts": 2}),
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    arn = sts.get_caller_identity()["Arn"]
    m = re.match(r"^arn:aws:sts::(\d+):assumed-role/([^/]+)/.+$", arn)
    assert m is not None, f"{why}: vended credentials are not an assumed-role session: {arn!r}"
    assert (m.group(1), m.group(2)) == (account_id, role_name), (
        f"{why}: vended credentials assumed {m.group(2)!r} in {m.group(1)!r}, expected "
        f"{role_name!r} in the caller's account"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
