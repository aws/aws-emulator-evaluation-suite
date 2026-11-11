"""xsvc-cognito-identity-3-cfn-principal-tag-mapping-gates-s3-read-by-session-tag."""
from __future__ import annotations

import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cognito-identity-3-cfn-principal-tag-mapping-gates-s3-read-by-session-tag"
GROUP = "deploy-downstream-principal"
SERVICES = ["cloudformation", "cognito-identity", "sts"]

_DENIED_CODE = "AccessDenied"
_STACK_BUDGET_S = 420.0
_PROPAGATION_BUDGET_S = 120.0
_TAG_KEY = "tenant"
_CLAIM = "custom:tenant"


def _template(names):
    """The whole estate as one stack. The federated role carries NO permission policy: every S3
    read below is granted only by the bucket policy's aws:PrincipalTag condition."""
    bucket = names["bucket"]

    def _tenant_allow(tenant):
        return {
            "Sid": f"Allow{tenant.capitalize()}TenantPrefix",
            "Effect": "Allow",
            "Principal": {"AWS": {"Fn::GetAtt": ["FederatedRole", "Arn"]}},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/tenants/{tenant}/*",
            "Condition": {"StringEquals": {f"aws:PrincipalTag/{_TAG_KEY}": tenant}},
        }

    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "UserPool": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {
                    "UserPoolName": names["user_pool"],
                    "Schema": [{"Name": "tenant", "AttributeDataType": "String",
                                "Mutable": True}],
                    "Policies": {"PasswordPolicy": {
                        "MinimumLength": 12, "RequireLowercase": True, "RequireUppercase": True,
                        "RequireNumbers": True, "RequireSymbols": False}},
                    "UserPoolTags": {"sim2real": "xsvc-cognito-identity-3"},
                },
            },
            "UserPoolClient": {
                "Type": "AWS::Cognito::UserPoolClient",
                "Properties": {
                    "ClientName": names["client"],
                    "UserPoolId": {"Ref": "UserPool"},
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
                        "ClientId": {"Ref": "UserPoolClient"},
                        "ProviderName": {"Fn::GetAtt": ["UserPool", "ProviderName"]},
                    }],
                    "IdentityPoolTags": [{"Key": "sim2real", "Value": "xsvc-cognito-identity-3"}],
                },
            },
            "FederatedRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": names["role"],
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                            "Action": ["sts:AssumeRoleWithWebIdentity", "sts:TagSession"],
                            "Condition": {
                                "StringEquals": {
                                    "cognito-identity.amazonaws.com:aud": {"Ref": "IdentityPool"}},
                                "ForAnyValue:StringLike": {
                                    "cognito-identity.amazonaws.com:amr": "authenticated"},
                            },
                        }],
                    },
                    "Tags": [{"Key": "sim2real", "Value": "xsvc-cognito-identity-3"}],
                },
            },
            "RoleAttachment": {
                "Type": "AWS::Cognito::IdentityPoolRoleAttachment",
                "Properties": {
                    "IdentityPoolId": {"Ref": "IdentityPool"},
                    "Roles": {"authenticated": {"Fn::GetAtt": ["FederatedRole", "Arn"]}},
                },
            },
            "PrincipalTagMap": {
                "Type": "AWS::Cognito::IdentityPoolPrincipalTag",
                "Properties": {
                    "IdentityPoolId": {"Ref": "IdentityPool"},
                    "IdentityProviderName": {"Fn::GetAtt": ["UserPool", "ProviderName"]},
                    "UseDefaults": False,
                    "PrincipalTags": {_TAG_KEY: _CLAIM},
                },
            },
            "Bucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": bucket,
                    "Tags": [{"Key": "sim2real", "Value": "xsvc-cognito-identity-3"}],
                },
            },
            "BucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "Properties": {
                    "Bucket": {"Ref": "Bucket"},
                    "PolicyDocument": {"Version": "2012-10-17",
                                       "Statement": [_tenant_allow("alpha"),
                                                     _tenant_allow("beta")]},
                },
            },
        },
        "Outputs": {
            "IdentityPoolId": {"Value": {"Ref": "IdentityPool"}},
            "UserPoolId": {"Value": {"Ref": "UserPool"}},
            "UserPoolClientId": {"Value": {"Ref": "UserPoolClient"}},
            "ProviderName": {"Value": {"Fn::GetAtt": ["UserPool", "ProviderName"]}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["FederatedRole", "Arn"]}},
        },
    })


def _retry(fn, *, retryable, timeout_s, interval_s=3.0, description):
    """Bounded retry over the listed error codes only (IAM / role-mapping propagation)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in retryable or time.monotonic() >= deadline:
                raise AssertionError(f"{description} failed: {code!r}: {exc}") from exc
        time.sleep(interval_s)


def _stack_failure_reasons(cfn, stack):
    try:
        events = cfn.describe_stack_events(StackName=stack)["StackEvents"]
    except ClientError as exc:
        return [f"describe_stack_events failed: {exc}"]
    return [f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason')}" for e in events
            if e["ResourceStatus"].endswith("_FAILED")][:6]


def _wait_stack(cfn, stack, want, timeout_s):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if want == "DELETE_COMPLETE" and "does not exist" in str(exc):
                return want
            raise
        if status == want:
            return status
        if status.endswith("_FAILED") or status in ("ROLLBACK_COMPLETE", "DELETE_COMPLETE"):
            break
        time.sleep(5.0)
    raise AssertionError(f"stack {stack} reached {status!r}, wanted {want!r}; failures: "
                         f"{_stack_failure_reasons(cfn, stack)!r}")


def _delete_stack(cfn, stack):
    """Never raises: on_cleanup swallows exceptions, so a failed teardown must print to be seen."""
    try:
        cfn.delete_stack(StackName=stack)
        _wait_stack(cfn, stack, "DELETE_COMPLETE", _STACK_BUDGET_S)
    except (ClientError, AssertionError) as exc:
        raise RuntimeError(
            f"CloudFormation stack {stack} did not delete cleanly: {exc}"
        ) from exc


def _empty_bucket(s3, bucket):
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})


def _client_from_credentials(ctx, service, creds, attempt=0):
    """A client signed with vended temporary credentials, handed over by value (never os.environ).
    A distinct ``attempt`` yields a distinct client (and connection) for the same credentials."""
    return ctx.client(
        service,
        config=Config(retries={"max_attempts": 2}, user_agent_extra=f"sim2real-attempt-{attempt}"),
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds.get("SecretKey") or creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _read(s3, bucket, key):
    """GetObject; return (body, None, None) or (None, Code, Message)."""
    try:
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read(), None, None
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return None, err.get("Code"), err.get("Message")


def _denied_message(arn, bucket, key):
    return (
        f"User: {arn} is not authorized to perform: s3:GetObject on resource: "
        f'"arn:aws:s3:::{bucket}/{key}" because no identity-based policy allows the s3:GetObject action'
    )


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-declared IdentityPoolPrincipalTag maps claim custom:tenant to session tag tenant, and
    S3 enforces it: alpha reads tenants/alpha/, while beta and an untagged user get AccessDenied.
    The federated role has no permission policy, so only the tag-conditioned bucket policy grants.
    """
    cfn = ctx.client("cloudformation")
    ci = ctx.client("cognito-identity")
    idp = ctx.client("cognito-idp")
    s3 = ctx.client("s3")

    suffix = uuid.uuid4().hex[:10]
    names = {
        "stack": f"sim2real-xsvc-ci3-ptag-{suffix}",
        "bucket": f"sim2real-xsvc-ci3-ptag-{suffix}",
        "user_pool": f"sim2real-xsvc-ci3-ptag-{suffix}",
        "client": f"sim2real-xsvc-ci3-ptag-{suffix}",
        "identity_pool": f"sim2real_xsvc_ci3_ptag_{suffix}",
        "role": f"sim2real-xsvc-ci3-ptag-{suffix}",
    }
    stack = names["stack"]

    # Registered before the create so a create that fails half-way is still torn down.
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))
    cfn.create_stack(
        StackName=stack, TemplateBody=_template(names),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": "xsvc-cognito-identity-3"}],
    )
    _wait_stack(cfn, stack, "CREATE_COMPLETE", _STACK_BUDGET_S)
    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cfn.describe_stacks(StackName=stack)["Stacks"][0]["Outputs"]}
    pool_id, user_pool_id = outputs["IdentityPoolId"], outputs["UserPoolId"]
    client_id, provider = outputs["UserPoolClientId"], outputs["ProviderName"]
    role_name = names["role"]
    provider_host, _, provider_pool = provider.partition("/")
    assert provider_pool == user_pool_id and provider_host.split(".")[:2] == ["cognito-idp", ctx.region], (
        f"UserPool ProviderName output {provider!r} does not name user pool {user_pool_id!r} in {ctx.region}"
    )

    tag_map = ci.get_principal_tag_attribute_map(IdentityPoolId=pool_id,
                                                 IdentityProviderName=provider)
    assert tag_map["PrincipalTags"] == {_TAG_KEY: _CLAIM}, (
        f"GetPrincipalTagAttributeMap returned {tag_map.get('PrincipalTags')!r}; the stack "
        f"declared {{{_TAG_KEY!r}: {_CLAIM!r}}}"
    )
    assert tag_map["UseDefaults"] is False, (
        f"the stack declared UseDefaults false; GetPrincipalTagAttributeMap says "
        f"{tag_map.get('UseDefaults')!r}"
    )
    assert tag_map["IdentityPoolId"] == pool_id and tag_map["IdentityProviderName"] == provider, (
        f"the map was reported for {tag_map.get('IdentityPoolId')!r}/"
        f"{tag_map.get('IdentityProviderName')!r}, not {pool_id!r}/{provider!r}"
    )

    # Emptied before the stack deletes the bucket (cleanup is LIFO).
    bucket = names["bucket"]
    ctx.on_cleanup(lambda: _empty_bucket(s3, bucket))
    bodies = {t: f"{t}-".encode() + uuid.uuid4().bytes for t in ("alpha", "beta")}
    keys = {t: f"tenants/{t}/data.bin" for t in bodies}
    for t, body in bodies.items():
        s3.put_object(Bucket=bucket, Key=keys[t], Body=body)

    def _session_for(tenant):
        username = f"sim2real-{tenant or 'none'}-{uuid.uuid4().hex[:8]}"
        password = "Sim2real" + uuid.uuid4().hex[:12] + "Q7"
        attrs = [{"Name": _CLAIM, "Value": tenant}] if tenant else []
        idp.admin_create_user(UserPoolId=user_pool_id, Username=username,
                              UserAttributes=attrs, MessageAction="SUPPRESS",
                              TemporaryPassword=password)
        idp.admin_set_user_password(UserPoolId=user_pool_id, Username=username,
                                    Password=password, Permanent=True)
        id_token = idp.admin_initiate_auth(
            UserPoolId=user_pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )["AuthenticationResult"]["IdToken"]
        logins = {provider: id_token}
        identity_id = ci.get_id(IdentityPoolId=pool_id, Logins=logins)["IdentityId"]
        ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))
        creds = _retry(
            lambda: ci.get_credentials_for_identity(IdentityId=identity_id, Logins=logins),
            retryable={"InvalidIdentityPoolConfigurationException", "AccessDenied",
                       "NotAuthorizedException"},
            timeout_s=_PROPAGATION_BUDGET_S,
            description=f"GetCredentialsForIdentity for the {tenant!r} user",
        )["Credentials"]
        arn = _client_from_credentials(ctx, "sts", creds).get_caller_identity()["Arn"]
        assert f":assumed-role/{role_name}/" in arn, (
            f"the {tenant!r} user's vended session is {arn!r}, not a session of {role_name!r}"
        )
        return creds, arn

    (alpha_creds, alpha_arn), (beta_creds, beta_arn) = _session_for("alpha"), _session_for("beta")
    untagged_creds, untagged_arn = _session_for(None)

    def _read_until_allowed(creds, key):
        """Positive legs only: bucket-policy evaluation is eventually consistent per S3 front end
        and a client pins one keep-alive connection, so each attempt uses a fresh client."""
        started = time.monotonic()
        attempt = 0
        while True:
            attempt += 1
            client = _client_from_credentials(ctx, "s3", creds, attempt)
            body, code, _ = _read(client, bucket, key)
            if body is not None or time.monotonic() - started >= _PROPAGATION_BUDGET_S:
                return body, code, client
            time.sleep(5.0)

    body, code, alpha = _read_until_allowed(alpha_creds, keys["alpha"])
    assert body == bodies["alpha"], (
        f"the alpha user (tag {_TAG_KEY}=alpha) read tenants/alpha/ -> {body!r} / {code!r}; "
        f"expected {bodies['alpha']!r} — the principal tag did not reach the session, or the "
        f"aws:PrincipalTag condition was not evaluated against it"
    )
    body, code, beta = _read_until_allowed(beta_creds, keys["beta"])
    assert body == bodies["beta"], (
        f"the beta user read its own tenants/beta/ -> {body!r} / {code!r}; expected "
        f"{bodies['beta']!r}"
    )
    untagged = _client_from_credentials(ctx, "s3", untagged_creds)

    body, code, message = _read(beta, bucket, keys["alpha"])
    assert body is None, f"the beta user READ tenants/alpha/: {body!r}"
    assert code == _DENIED_CODE, (
        f"beta user reading tenants/alpha/ returned {code!r}, expected {_DENIED_CODE!r}"
    )
    expected = _denied_message(beta_arn, bucket, keys["alpha"])
    assert message == expected, f"expected {expected!r}, got {message!r}"
    body, code, message = _read(alpha, bucket, keys["beta"])
    assert body is None, f"the alpha user READ tenants/beta/: {body!r}"
    assert code == _DENIED_CODE, (
        f"alpha user reading tenants/beta/ returned {code!r}, expected {_DENIED_CODE!r}"
    )
    expected = _denied_message(alpha_arn, bucket, keys["beta"])
    assert message == expected, f"expected {expected!r}, got {message!r}"
    body, code, message = _read(untagged, bucket, keys["alpha"])
    assert body is None, f"a user with NO {_CLAIM} claim READ tenants/alpha/: {body!r}"
    assert code == _DENIED_CODE, (
        f"untagged user reading tenants/alpha/ returned {code!r}, expected {_DENIED_CODE!r}"
    )
    expected = _denied_message(untagged_arn, bucket, keys["alpha"])
    assert message == expected, f"expected {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
