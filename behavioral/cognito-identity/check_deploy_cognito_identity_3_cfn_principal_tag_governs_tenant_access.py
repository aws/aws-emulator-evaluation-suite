"""deploy-cognito-identity-3-cfn-principal-tag-governs-tenant-access."""
from __future__ import annotations

import base64
import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cognito-identity-3-cfn-principal-tag-governs-tenant-access"
GROUP = "deploy-cfn-principal-tag"
SERVICES = ["cognito-identity"]

# AWS behaviour:
# - AWS::Cognito::IdentityPoolPrincipalTag has the compound primary identifier
#   [IdentityPoolId, IdentityProviderName], so its Ref is "<pool id>|<provider name>".
# - SetPrincipalTagAttributeMap with UseDefaults=true REPLACES any supplied PrincipalTags with the
#   user-pool default mapping {"client": "aud", "username": "sub"}.
# - S3 refuses a policy-scoped read with `AccessDenied` and attributes it to the identity policy.
DENIED_CODE = "AccessDenied"
DEFAULT_MAP = {"client": "aud", "username": "sub"}
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


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed IdentityPoolPrincipalTag maps a user-pool claim to the session tag that alone
    scopes which tenant's S3 objects vended credentials read; in-place updates move enforcement to
    the new tag key, and UseDefaults=true swaps in the default claim mapping.
    """
    cfn = ctx.client("cloudformation")
    ci = ctx.client("cognito-identity")
    idp = ctx.client("cognito-idp")
    s3 = ctx.client("s3")

    stack_name = ctx.unique_name("sim2real-cfn-cip-ptag-")
    names = {
        "user_pool": ctx.unique_name("sim2real-cip-ptag-up-"),
        "client": "sim2real-cip-ptag-client",
        "identity_pool": ctx.unique_name("sim2real_cip_ptag_").replace("-", "_"),
        "bucket": ctx.unique_name("sim2real-cip-ptag-").lower()[:63],
        "role": ctx.unique_name("sim2real-cip-ptag-role-")[:64],
    }

    # ---- phase 1: deploy with PrincipalTags {tenant: custom:tenant}
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(names, {"tenant": "custom:tenant"}, False),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    _wait_stack(ctx, cfn, stack_name, _TERMINAL_OK)
    out = _stack_outputs(cfn, stack_name)

    user_pool_id = out["UserPoolId"]
    client_id = out["ClientId"]
    pool_id = out["IdentityPoolId"]
    provider = out["ProviderName"]
    bucket = out["BucketName"]
    assert provider.rpartition("/")[2] == user_pool_id, (
        f"UserPool ProviderName {provider!r} is not the issuer form for pool {user_pool_id!r}"
    )
    assert out["PrincipalTagRef"] == f"{pool_id}|{provider}", (
        f"Ref of AWS::Cognito::IdentityPoolPrincipalTag was {out['PrincipalTagRef']!r}, expected "
        f"'<pool id>|<provider name>' = {pool_id + '|' + provider!r}"
    )
    ptag_physical = _physical_id(cfn, stack_name, "PrincipalTag")
    pool_physical = _physical_id(cfn, stack_name, "IdentityPool")
    assert ptag_physical == out["PrincipalTagRef"], (
        f"PrincipalTag physical id {ptag_physical!r} differs from its Ref {out['PrincipalTagRef']!r}"
    )

    stored = ci.get_principal_tag_attribute_map(IdentityPoolId=pool_id,
                                                IdentityProviderName=provider)
    assert stored.get("PrincipalTags") == {"tenant": "custom:tenant"}, (
        f"GetPrincipalTagAttributeMap returned {stored.get('PrincipalTags')!r}, expected the "
        f"CFN-declared {{'tenant': 'custom:tenant'}}"
    )
    assert stored.get("UseDefaults") is False, (
        f"CFN declared UseDefaults=false, the service reports {stored.get('UseDefaults')!r}"
    )

    # Two users, one per tenant; the tenant is a custom claim on each user's ID token.
    users = {}
    for tenant in ("tenant-a", "tenant-b"):
        username = ctx.unique_name("sim2real-cip-ptag-user-")
        password = "Sim2Real!" + uuid.uuid4().hex[:12]
        created = idp.admin_create_user(
            UserPoolId=user_pool_id, Username=username, MessageAction="SUPPRESS",
            UserAttributes=[{"Name": "custom:tenant", "Value": tenant}],
        )
        ctx.on_cleanup(lambda u=username: idp.admin_delete_user(UserPoolId=user_pool_id,
                                                                Username=u))
        sub = {a["Name"]: a["Value"] for a in created["User"]["Attributes"]}["sub"]
        idp.admin_set_user_password(UserPoolId=user_pool_id, Username=username,
                                    Password=password, Permanent=True)
        token = idp.admin_initiate_auth(
            UserPoolId=user_pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )["AuthenticationResult"]["IdToken"]
        issuer = _jwt_claims(token)["iss"]
        assert issuer == f"https://{provider}", (
            f"the ID token issuer {issuer!r} is not the pool's ProviderName {provider!r}"
        )
        logins = {provider: token}
        identity_id = ci.get_id(IdentityPoolId=pool_id, Logins=logins)["IdentityId"]
        ctx.on_cleanup(lambda i=identity_id: ci.delete_identities(IdentityIdsToDelete=[i]))
        users[tenant] = {"sub": sub, "logins": logins, "identity": identity_id}
    assert users["tenant-a"]["identity"] != users["tenant-b"]["identity"], (
        f"both tenants' logins collapsed onto identity {users['tenant-a']['identity']!r}"
    )

    # Objects under three prefixes, one per tag key the role policy scopes on.
    payloads = {}
    for tenant, u in users.items():
        for key in (f"tenant/{tenant}/obj", f"org/{tenant}/obj", f"user/{u['sub']}/obj"):
            body = f"sim2real-{key}-".encode() + uuid.uuid4().bytes
            s3.put_object(Bucket=bucket, Key=key, Body=body)
            ctx.on_cleanup(lambda k=key: s3.delete_object(Bucket=bucket, Key=k))
            payloads[key] = body

    sub_a = users["tenant-a"]["sub"]
    sub_b = users["tenant-b"]["sub"]
    # Every vended session is the stack's role under Cognito's fixed session name.
    session_arn = (
        f"arn:aws:sts::{ctx.account}:assumed-role/{names['role']}/CognitoIdentityCredentials"
    )

    def _assert_denied(client, key, why):
        _assert_refused(client, bucket, key, why, session_arn)

    # phase 1 assertions: the tenant tag governs; no org/username tag exists yet.
    s3_a = _wait_for_read(ctx, ci, users["tenant-a"], bucket, "tenant/tenant-a/obj", payloads)
    s3_b = _wait_for_read(ctx, ci, users["tenant-b"], bucket, "tenant/tenant-b/obj", payloads)
    _assert_denied(s3_a, "tenant/tenant-b/obj", "phase 1, cross-tenant via tenant tag")
    _assert_denied(s3_b, "tenant/tenant-a/obj", "phase 1, reverse cross-tenant")
    _assert_denied(s3_a, "org/tenant-a/obj", "phase 1, org tag not yet mapped")
    _assert_denied(s3_a, f"user/{sub_a}/obj", "phase 1, username tag not mapped")

    # ---- phase 2: in-place update of PrincipalTags only, through a change set
    changes = _change_set(ctx, cfn, stack_name, _template(names, {"org": "custom:tenant"}, False))
    assert [(c["LogicalResourceId"], c["Action"], c.get("Replacement")) for c in changes] == [
        ("PrincipalTag", "Modify", "False")
    ], f"changing only PrincipalTags must be one non-replacing Modify, change set was {changes!r}"
    _wait_stack(ctx, cfn, stack_name, _TERMINAL_OK)
    assert _physical_id(cfn, stack_name, "IdentityPool") == pool_physical, (
        "the identity pool was replaced by a PrincipalTags-only update"
    )
    assert _physical_id(cfn, stack_name, "PrincipalTag") == ptag_physical, (
        "the PrincipalTag resource was replaced by an update to a mutable property"
    )
    stored = ci.get_principal_tag_attribute_map(IdentityPoolId=pool_id,
                                                IdentityProviderName=provider)
    assert stored.get("PrincipalTags") == {"org": "custom:tenant"}, (
        f"after the in-place update the map reads {stored.get('PrincipalTags')!r}, expected "
        f"{{'org': 'custom:tenant'}}"
    )
    assert stored.get("UseDefaults") is False, (
        f"UseDefaults moved to {stored.get('UseDefaults')!r} on a PrincipalTags-only update"
    )

    s3_a = _wait_for_read(ctx, ci, users["tenant-a"], bucket, "org/tenant-a/obj", payloads)
    s3_b = _wait_for_read(ctx, ci, users["tenant-b"], bucket, "org/tenant-b/obj", payloads)
    _assert_denied(s3_a, "org/tenant-b/obj", "phase 2, cross-tenant via org tag")
    _assert_denied(s3_b, "org/tenant-a/obj", "phase 2, reverse cross-tenant")
    _assert_denied(s3_a, "tenant/tenant-a/obj", "phase 2, old tenant key no longer mapped")

    # ---- phase 3: UseDefaults true replaces the map with the default claims
    _update_stack(ctx, cfn, stack_name, _template(names, {"org": "custom:tenant"}, True))
    assert _physical_id(cfn, stack_name, "IdentityPool") == pool_physical, (
        "the identity pool was replaced by a UseDefaults-only update"
    )
    stored = ci.get_principal_tag_attribute_map(IdentityPoolId=pool_id,
                                                IdentityProviderName=provider)
    assert stored.get("UseDefaults") is True, (
        f"CFN declared UseDefaults=true, the service reports {stored.get('UseDefaults')!r}"
    )
    assert stored.get("PrincipalTags") == DEFAULT_MAP, (
        f"with UseDefaults=true the map must be the default {DEFAULT_MAP!r}, got "
        f"{stored.get('PrincipalTags')!r}"
    )

    s3_a = _wait_for_read(ctx, ci, users["tenant-a"], bucket, f"user/{sub_a}/obj", payloads)
    _assert_denied(s3_a, f"user/{sub_b}/obj", "phase 3, other user's sub prefix")
    _assert_denied(s3_a, "org/tenant-a/obj", "phase 3, org mapping replaced by defaults")


def _template(names: dict, principal_tags: dict, use_defaults: bool) -> str:
    bucket_arn = {"Fn::GetAtt": ["Bucket", "Arn"]}

    def _scoped(prefix_and_var):
        return {"Fn::Join": ["", [bucket_arn, prefix_and_var]]}

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
                    "ClientName": names["client"],
                    "GenerateSecret": False,
                    "ExplicitAuthFlows": ["ALLOW_ADMIN_USER_PASSWORD_AUTH",
                                          "ALLOW_REFRESH_TOKEN_AUTH"],
                },
            },
            "IdentityPool": {
                "Type": "AWS::Cognito::IdentityPool",
                "Properties": {
                    "IdentityPoolName": names["identity_pool"],
                    "AllowUnauthenticatedIdentities": False,
                    "CognitoIdentityProviders": [{
                        "ProviderName": {"Fn::GetAtt": ["UserPool", "ProviderName"]},
                        "ClientId": {"Ref": "UserPoolClient"},
                        "ServerSideTokenCheck": False,
                    }],
                    "IdentityPoolTags": [{"Key": "sim2real", "Value": CHECK}],
                },
            },
            "PrincipalTag": {
                "Type": "AWS::Cognito::IdentityPoolPrincipalTag",
                "Properties": {
                    "IdentityPoolId": {"Ref": "IdentityPool"},
                    "IdentityProviderName": {"Fn::GetAtt": ["UserPool", "ProviderName"]},
                    "PrincipalTags": principal_tags,
                    "UseDefaults": use_defaults,
                },
            },
            "Bucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": names["bucket"],
                    "Tags": [{"Key": "sim2real", "Value": CHECK}],
                },
            },
            "TenantRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": names["role"],
                    "Description": "sim2real deploy probe role for Cognito Identity principal tags",
                    "Tags": [{"Key": "sim2real", "Value": CHECK}],
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                            "Action": ["sts:AssumeRoleWithWebIdentity", "sts:TagSession"],
                            "Condition": {
                                "StringEquals": {
                                    "cognito-identity.amazonaws.com:aud": {"Ref": "IdentityPool"}
                                },
                                "ForAnyValue:StringLike": {
                                    "cognito-identity.amazonaws.com:amr": "authenticated"
                                },
                            },
                        }],
                    },
                    "Policies": [{
                        "PolicyName": "sim2real-tenant-scoped-read",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": "s3:GetObject",
                                "Resource": [
                                    _scoped("/tenant/${aws:PrincipalTag/tenant}/*"),
                                    _scoped("/org/${aws:PrincipalTag/org}/*"),
                                    _scoped("/user/${aws:PrincipalTag/username}/*"),
                                ],
                            }],
                        },
                    }],
                },
            },
            "RoleAttachment": {
                "Type": "AWS::Cognito::IdentityPoolRoleAttachment",
                "Properties": {
                    "IdentityPoolId": {"Ref": "IdentityPool"},
                    "Roles": {"authenticated": {"Fn::GetAtt": ["TenantRole", "Arn"]}},
                },
            },
        },
        "Outputs": {
            "UserPoolId": {"Value": {"Ref": "UserPool"}},
            "ClientId": {"Value": {"Ref": "UserPoolClient"}},
            "IdentityPoolId": {"Value": {"Ref": "IdentityPool"}},
            "ProviderName": {"Value": {"Fn::GetAtt": ["UserPool", "ProviderName"]}},
            "PrincipalTagRef": {"Value": {"Ref": "PrincipalTag"}},
            "BucketName": {"Value": {"Ref": "Bucket"}},
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


def _physical_id(cfn, stack_name: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(
        StackName=stack_name, LogicalResourceId=logical_id
    )["StackResourceDetail"]["PhysicalResourceId"]


def _change_set(ctx, cfn, stack_name: str, template_body: str) -> list:
    """Create a change set for template_body, return its resource changes, then execute it."""
    cs_name = "sim2real-ptag-" + uuid.uuid4().hex[:8]
    cfn.create_change_set(StackName=stack_name, ChangeSetName=cs_name,
                          TemplateBody=template_body, Capabilities=["CAPABILITY_NAMED_IAM"])
    deadline = time.time() + _budget_s(ctx, 300)
    while True:
        cs = cfn.describe_change_set(StackName=stack_name, ChangeSetName=cs_name)
        if cs["Status"] == "CREATE_COMPLETE":
            break
        assert cs["Status"] in ("CREATE_PENDING", "CREATE_IN_PROGRESS"), (
            f"change set {cs_name} became {cs['Status']!r}: {cs.get('StatusReason')!r}"
        )
        if time.time() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"change set {cs_name} CREATE_COMPLETE: the run budget ended first; not graded")
        assert time.time() < deadline, f"change set {cs_name} still {cs['Status']!r}"
        time.sleep(1.0)
    changes = [c["ResourceChange"] for c in cs["Changes"] if c.get("Type") == "Resource"]
    cfn.execute_change_set(StackName=stack_name, ChangeSetName=cs_name)
    return changes


def _update_stack(ctx, cfn, stack_name: str, template_body: str) -> None:
    cfn.update_stack(StackName=stack_name, TemplateBody=template_body,
                     Capabilities=["CAPABILITY_NAMED_IAM"])
    _wait_stack(ctx, cfn, stack_name, _TERMINAL_OK)


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


def _client_from_credentials(ctx, service, creds):
    """A client on the target signed with vended temporary credentials, never os.environ."""
    return ctx.client(
        service,
        config=Config(retries={"max_attempts": 2}),
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _jwt_claims(token):
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _read(client, bucket, key):
    """GetObject; (body, None, None) on success, (None, code, message) if refused."""
    try:
        return client.get_object(Bucket=bucket, Key=key)["Body"].read(), None, None
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return None, err.get("Code"), err.get("Message") or ""


def _vend(ctx, ci, user, timeout_s=120.0):
    """GetCredentialsForIdentity, retrying only the transient role-propagation refusals."""
    deadline = time.time() + _budget_s(ctx, timeout_s)
    while True:
        try:
            return ci.get_credentials_for_identity(
                IdentityId=user["identity"], Logins=user["logins"]
            )["Credentials"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _TRANSIENT_VEND or time.time() >= deadline:
                if code in _TRANSIENT_VEND and _budget_spent(ctx):
                    raise TimeoutError("GetCredentialsForIdentity past role propagation: the run budget ended first; not graded") from exc
                raise
            time.sleep(1.0)


def _wait_for_read(ctx, ci, user, bucket, key, payloads, timeout_s=180.0):
    """Mint fresh credentials until they read `key` with its exact bytes; return that S3 client.

    The returned client's credentials are the ones that proved the CURRENT mapping is in force, so
    every denial asserted with it afterwards is about the same tag set, not a stale one.
    """
    deadline = time.time() + _budget_s(ctx, timeout_s)
    last = None
    while time.time() < deadline:
        client = _client_from_credentials(ctx, "s3", _vend(ctx, ci, user))
        body, code, msg = _read(client, bucket, key)
        if body is not None:
            assert body == payloads[key], f"read {key!r} returned {body!r}, expected {payloads[key]!r}"
            return client
        last = (code, msg)
        time.sleep(1.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"credentials able to read their own {key!r}: the run budget ended first; not graded")
    raise AssertionError(f"credentials never became able to read their own {key!r}: last={last!r}")


def _assert_refused(client, bucket, key, why, session_arn):
    body, code, msg = _read(client, bucket, key)
    assert code is not None, f"{why}: read of {key!r} was allowed and returned {body!r}"
    assert code == DENIED_CODE, f"{why}: expected {DENIED_CODE!r} for {key!r}, got {code!r}: {msg!r}"
    assert body is None, f"{why}: a refused GetObject returned a body {body!r}"
    expected = (
        f"User: {session_arn} is not authorized to perform: s3:GetObject on resource: "
        f'"arn:aws:s3:::{bucket}/{key}" because no identity-based policy allows the '
        "s3:GetObject action"
    )
    assert msg == expected, f"{why}: expected refusal message {expected!r}, got {msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
