"""principal-tag-condition-denies-the-other-tenants-object."""
from __future__ import annotations

import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "principal-tag-condition-denies-the-other-tenants-object"
GROUP = 'overly-permissive'
SERVICES = ['cognito-identity']

# S3 GetObject reports a policy refusal as `AccessDenied` (no `Exception` suffix), and the message
# attributes it to the missing identity-based policy, which shows the policy variable resolved to
# the OTHER tenant rather than the statement being broken.
DENIED_CODE = "AccessDenied"
_TRANSIENT_SET_ROLES = (
    "AccessDenied", "AccessDeniedException", "InvalidParameterException",
    "ThrottlingException", "TooManyRequestsException", "ConcurrentModificationException",
)


def _poll_until(fn, pred, timeout_s=180.0, interval_s=3.0, description="condition"):
    """Poll fn() until pred(result) or the deadline; ClientErrors count as not-yet."""
    deadline = time.time() + timeout_s
    last = None
    last_exc = None
    while time.time() < deadline:
        try:
            last = fn()
            if pred(last):
                return last
            last_exc = None
        except ClientError as exc:
            last_exc = exc
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}: last={last!r} err={last_exc!r}"
    )


def _set_roles(ci, pool_id, roles, timeout_s=180.0):
    """SetIdentityPoolRoles, retrying only the transient IAM-role-propagation rejections."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return ci.set_identity_pool_roles(IdentityPoolId=pool_id, Roles=roles)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _TRANSIENT_SET_ROLES or time.time() >= deadline:
                raise
            time.sleep(3.0)


def _client_from_credentials(ctx, service, creds):
    """A client for ``service`` on the same target, signed with the vended temporary credentials.

    The credentials go to ``ctx.client`` by value and are never written into os.environ, so
    nothing else in the process can pick them up.
    """
    return ctx.client(
        service,
        config=Config(retries={"max_attempts": 2}),
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds.get("SecretKey") or creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _denied_message(role_arn, bucket, key):
    """S3's refusal of GetObject for a Cognito-vended session of ``role_arn`` with no allowing
    identity-based policy."""
    account = role_arn.split(":")[4]
    role_name = role_arn.rsplit("/", 1)[-1]
    return (
        f"User: arn:aws:sts::{account}:assumed-role/{role_name}/CognitoIdentityCredentials is not "
        f"authorized to perform: s3:GetObject on resource: \"arn:aws:s3:::{bucket}/{key}\" "
        "because no identity-based policy allows the s3:GetObject action"
    )


def _read(client, bucket, key):
    """GetObject; return (body_bytes, None, None) on success or (None, Code, Message) if refused."""
    try:
        return client.get_object(Bucket=bucket, Key=key)["Body"].read(), None, None
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return None, err.get("Code"), err.get("Message") or ""


# ===== check =====

@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A principal-tag mapping turns a user-pool claim into a session tag, so a policy scoped by
    ${aws:PrincipalTag/tenant} lets each identity read only its own object; both cross-tenant
    reads are refused with AccessDenied.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/attributes-for-access-control.html
    """
    ci = ctx.client("cognito-identity")
    idp = ctx.client("cognito-idp")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    # ---- two tenants' objects in one bucket
    bucket = ctx.unique_name("sim2real-behav-tenants-")
    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    payloads = {
        "tenant-a": b"sim2real-tenant-a-" + uuid.uuid4().bytes,
        "tenant-b": b"sim2real-tenant-b-" + uuid.uuid4().bytes,
    }
    for tenant, payload in payloads.items():
        key = f"{tenant}/obj"
        s3.put_object(Bucket=bucket, Key=key, Body=payload)
        ctx.on_cleanup(lambda key=key: s3.delete_object(Bucket=bucket, Key=key))

    # ---- a real user pool: the tenant is a custom claim on the user, and Cognito Identity
    # rejects fabricated tokens, so a genuine user-pool JWT is the only self-contained login.
    user_pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-tenant-up-"),
        Schema=[{
            "Name": "tenant",
            "AttributeDataType": "String",
            "Mutable": True,
            "Required": False,
            "StringAttributeConstraints": {"MinLength": "1", "MaxLength": "64"},
        }],
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=user_pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=user_pool_id,
        ClientName="sim2real-behav-tenant-client",
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    provider = f"cognito-idp.{ctx.region}.amazonaws.com/{user_pool_id}"

    def _mint_id_token(tenant):
        username = ctx.unique_name("sim2real-behav-tenant-user-")
        password = "Sim2Real!" + uuid.uuid4().hex[:12]
        idp.admin_create_user(
            UserPoolId=user_pool_id, Username=username, MessageAction="SUPPRESS",
            UserAttributes=[{"Name": "custom:tenant", "Value": tenant}],
        )
        ctx.on_cleanup(
            lambda: idp.admin_delete_user(UserPoolId=user_pool_id, Username=username)
        )
        idp.admin_set_user_password(
            UserPoolId=user_pool_id, Username=username, Password=password, Permanent=True
        )
        return idp.admin_initiate_auth(
            UserPoolId=user_pool_id, ClientId=client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )["AuthenticationResult"]["IdToken"]

    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_behav_tenant_").replace("-", "_"),
        AllowUnauthenticatedIdentities=False,
        CognitoIdentityProviders=[{
            "ProviderName": provider, "ClientId": client_id, "ServerSideTokenCheck": False,
        }],
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    # ---- one role for both tenants; only the session tag separates them
    role_name = ctx.unique_name("sim2real-behav-tenant-role-")[:64]
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                # With a PrincipalTags mapping, credentials are not vended without sts:TagSession.
                "Action": ["sts:AssumeRoleWithWebIdentity", "sts:TagSession"],
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id}
                },
            }],
        }),
        Description="sim2real behavioral probe role for Cognito Identity",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "sim2real-behav-tenant-grant"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/${{aws:PrincipalTag/tenant}}/*",
            }],
        }),
    )
    # Registered after delete_role so LIFO cleanup drops the inline policy first.
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name,
                                                  PolicyName=policy_name))
    _set_roles(ci, pool_id, {"authenticated": role_arn})

    # The mapping is authored as {tag-name: claim-name}.
    ci.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=provider,
        UseDefaults=False, PrincipalTags={"tenant": "custom:tenant"},
    )
    stored = ci.get_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=provider
    )
    assert stored.get("PrincipalTags") == {"tenant": "custom:tenant"}, (
        f"GetPrincipalTagAttributeMap returned {stored.get('PrincipalTags')!r}, expected the "
        f"mapping just set"
    )
    assert stored.get("UseDefaults") is False, (
        f"UseDefaults was set to False, GetPrincipalTagAttributeMap reports "
        f"{stored.get('UseDefaults')!r}"
    )

    def _credentials_for(tenant):
        logins = {provider: _mint_id_token(tenant)}
        identity_id = ci.get_id(IdentityPoolId=pool_id, Logins=logins)["IdentityId"]
        ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))
        vended = _poll_until(
            lambda: ci.get_credentials_for_identity(IdentityId=identity_id, Logins=logins),
            lambda r: "Credentials" in r and r["Credentials"].get("SessionToken"),
            timeout_s=120.0,
            description=f"credentials to be vended for the {tenant} identity",
        )
        return identity_id, vended["Credentials"]

    identity_a, creds_a = _credentials_for("tenant-a")
    identity_b, creds_b = _credentials_for("tenant-b")
    assert identity_a != identity_b, (
        f"the two tenants' logins collapsed onto one identity {identity_a!r}, so nothing below "
        f"distinguishes them"
    )
    s3_a = _client_from_credentials(ctx, "s3", creds_a)
    s3_b = _client_from_credentials(ctx, "s3", creds_b)

    # ---- positive control: each tenant reads its own object, exact bytes
    a_body = _poll_until(
        lambda: _read(s3_a, bucket, "tenant-a/obj"),
        lambda r: r[0] is not None,
        timeout_s=180.0,
        interval_s=5.0,
        description="tenant-a's session to be allowed its own object",
    )[0]
    assert a_body == payloads["tenant-a"], (
        f"tenant-a read {a_body!r}, expected {payloads['tenant-a']!r}"
    )
    b_body, b_code, b_msg = _read(s3_b, bucket, "tenant-b/obj")
    assert b_body == payloads["tenant-b"], (
        f"tenant-b read {b_body!r} (code {b_code!r}: {b_msg!r}), expected "
        f"{payloads['tenant-b']!r} — the policy is broken rather than tenant-scoped"
    )

    # ---- the one thing changed: the key names the other tenant's prefix
    cross_body, cross_code, cross_msg = _read(s3_a, bucket, "tenant-b/obj")
    assert cross_code is not None, (
        f"tenant-a's session read tenant-b's object; the ${{aws:PrincipalTag/tenant}} scope "
        f"granted nothing it should have: got {cross_body!r}"
    )
    assert cross_code == DENIED_CODE, (
        f"expected {DENIED_CODE!r} for a cross-tenant read, got {cross_code!r}: {cross_msg!r}"
    )
    assert cross_body is None, (
        f"a denied GetObject returned a body: {cross_body!r}"
    )
    assert cross_msg == _denied_message(role_arn, bucket, "tenant-b/obj"), (
        f"the refusal must attribute itself to the identity-based policy — that is what shows the "
        f"tag resolved to tenant-a rather than the statement being inert: expected "
        f"{_denied_message(role_arn, bucket, 'tenant-b/obj')!r}, got {cross_msg!r}"
    )

    # ---- and the mirror direction, so the scope is not simply a constant
    reverse_body, reverse_code, reverse_msg = _read(s3_b, bucket, "tenant-a/obj")
    assert reverse_code == DENIED_CODE, (
        f"tenant-b reading tenant-a's object must be refused with {DENIED_CODE!r}, got "
        f"{reverse_code!r}: {reverse_msg!r}"
    )
    assert reverse_body is None, (
        f"a denied GetObject returned a body: {reverse_body!r}"
    )
    assert reverse_msg == _denied_message(role_arn, bucket, "tenant-a/obj"), (
        f"expected {_denied_message(role_arn, bucket, 'tenant-a/obj')!r}, got {reverse_msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
