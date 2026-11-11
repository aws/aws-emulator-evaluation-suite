"""e2e-principal-tags-federation-to-sts-session-tags."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-principal-tags-federation-to-sts-session-tags"
GROUP = "e2e"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Principal tags configured on a developer-authenticated identity pool propagate all the
    way to the STS session (verified via an S3 ABAC condition that only the correct tag value
    satisfies), and credential issuance for the pool fails once the pool is deleted."""
    cognito = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    dev_provider = ctx.unique_name("sim2real-behav-dp-")
    pool_name = ctx.unique_name("sim2real-behav-pool-")
    # A federated (social) provider is registered too, purely so that SetPrincipalTagAttributeMap
    # -- which validates IdentityProviderName against a provider actually configured on the pool --
    # has a legal target. The federated provider is never used to authenticate; the actual tag
    # propagation under test flows through GetOpenIdTokenForDeveloperIdentity's own PrincipalTags
    # argument (which Cognito documents as configuring the tags for that token directly).
    social_provider_name = "graph.facebook.com"
    pool_id = cognito.create_identity_pool(
        IdentityPoolName=pool_name,
        # Unauthenticated identities stay enabled solely so the enhanced (GetCredentialsForIdentity)
        # flow has a legal, empirically-supported target: Cognito rejects both the raw developer
        # Logins pair ("Please provide a valid public provider") and the pool's own
        # GetOpenIdTokenForDeveloperIdentity-issued token ("Can't pass in a Cognito token") when
        # handed to GetCredentialsForIdentity for a developer-authenticated identity -- that flow is
        # basic-auth-only (AssumeRoleWithWebIdentity), exercised separately below.
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=dev_provider,
        SupportedLoginProviders={social_provider_name: "sim2real-behav-fb-app-id"},
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]

    pool_deleted = {"done": False}

    def _cleanup_pool():
        if not pool_deleted["done"]:
            try:
                cognito.delete_identity_pool(IdentityPoolId=pool_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup_pool)

    bucket_name = ctx.unique_name("sim2real-behav-tags-").lower().replace("_", "-")
    create_kwargs = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    object_key = "secret.txt"
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket_name, object_key))
    s3.put_object(
        Bucket=bucket_name,
        Key=object_key,
        Body=b"top-secret-payload",
        Tagging="department=engineering",
    )

    role_name = ctx.unique_name("sim2real-behav-role-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": ["sts:AssumeRoleWithWebIdentity", "sts:TagSession"],
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "authenticated"},
                },
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    permission_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/{object_key}",
                "Condition": {
                    "StringEquals": {
                        "s3:ExistingObjectTag/department": "${aws:PrincipalTag/department}"
                    }
                },
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="abac-s3-department",
        PolicyDocument=json.dumps(permission_policy),
    )

    # A distinct, unprivileged unauthenticated role -- required only so GetCredentialsForIdentity
    # (the enhanced flow) has a legal target on THIS pool. Developer-authenticated identities can't
    # use the enhanced flow (see note above), so it is exercised here on an unauthenticated identity
    # instead, on the same pool used for the rest of the check.
    unauth_role_name = ctx.unique_name("sim2real-behav-unauth-role-")[:64]
    unauth_trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "unauthenticated"},
                },
            }
        ],
    }
    unauth_role_arn = iam.create_role(
        RoleName=unauth_role_name,
        AssumeRolePolicyDocument=json.dumps(unauth_trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=unauth_role_name))

    cognito.set_identity_pool_roles(
        IdentityPoolId=pool_id, Roles={"authenticated": role_arn, "unauthenticated": unauth_role_arn}
    )
    tag_map_resp = cognito.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id,
        IdentityProviderName=social_provider_name,
        UseDefaults=False,
        PrincipalTags={"department": "department"},
    )
    assert tag_map_resp["PrincipalTags"] == {"department": "department"}, tag_map_resp

    # IAM role propagation into the identity pool's role config is eventually consistent; poll
    # GetCredentialsForIdentity for the unauthenticated identity until it can assume the role.
    unauth_identity_id = cognito.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(
        lambda: cognito.delete_identities(IdentityIdsToDelete=[unauth_identity_id])
    )
    enhanced_creds = _wait_for_credentials_for_identity(cognito, unauth_identity_id)
    assert enhanced_creds["AccessKeyId"], enhanced_creds

    dev_user_id = ctx.unique_name("dev-user-")
    token_resp = cognito.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id,
        Logins={dev_provider: dev_user_id},
        PrincipalTags={"department": "engineering"},
    )
    identity_id = token_resp["IdentityId"]
    web_identity_token = token_resp["Token"]
    assert identity_id != unauth_identity_id, (identity_id, unauth_identity_id)


    base_sts = ctx.client("sts")
    session_name = ctx.unique_name("sess-")
    # IAM role trust-policy propagation is eventually consistent (no fixed SLA); poll rather than
    # assert immediately: https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency
    role_credentials = _wait_for_assume_role_with_web_identity(
        base_sts, role_arn, web_identity_token, session_name
    )

    role_creds = {
        "aws_access_key_id": role_credentials["AccessKeyId"],
        "aws_secret_access_key": role_credentials["SecretAccessKey"],
        "aws_session_token": role_credentials["SessionToken"],
    }
    role_s3 = ctx.client("s3", creds=role_creds)
    body = role_s3.get_object(Bucket=bucket_name, Key=object_key)["Body"].read()
    assert body == b"top-secret-payload", body

    # GetCallerIdentity confirms the STS session is the one assumed via the web-identity token
    # (its ARN carries the exact RoleSessionName we chose, not just any name), corroborating that
    # the session tags applied above (proven by the ABAC-gated GetObject succeeding) belong to
    # *this* federated session and not some other concurrently-assumed one.
    role_sts = ctx.client("sts", creds=role_creds)
    caller_identity = role_sts.get_caller_identity()
    assert role_name in caller_identity["Arn"], caller_identity["Arn"]
    assert caller_identity["Arn"].split("/")[-1] == session_name, caller_identity["Arn"]

    cognito.delete_identity_pool(IdentityPoolId=pool_id)
    pool_deleted["done"] = True

    describe_err = _client_error(lambda: cognito.describe_identity_pool(IdentityPoolId=pool_id))
    assert describe_err == ("ResourceNotFoundException", f"IdentityPool '{pool_id}' not found."), (
        describe_err
    )

    err = _client_error(
        lambda: cognito.get_open_id_token_for_developer_identity(
            IdentityPoolId=pool_id,
            Logins={dev_provider: ctx.unique_name("dev-user-")},
        )
    )
    assert err == ("ResourceNotFoundException", f"IdentityPool '{pool_id}' not found."), err


def _wait_for_credentials_for_identity(cognito, identity_id, timeout_s=60.0, interval_s=3.0):
    """IAM role propagation into SetIdentityPoolRoles is eventually consistent; poll rather than
    assert immediately."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return cognito.get_credentials_for_identity(IdentityId=identity_id)["Credentials"]
        except ClientError as exc:
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"get_credentials_for_identity never succeeded (IAM propagation?): {last_err}")


def _delete_bucket(s3, bucket_name, object_key):

    try:
        s3.delete_object(Bucket=bucket_name, Key=object_key)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    s3.delete_bucket(Bucket=bucket_name)


def _delete_role(iam, role_name):
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="abac-s3-department")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _wait_for_assume_role_with_web_identity(sts, role_arn, token, session_name, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role_with_web_identity(
                RoleArn=role_arn, RoleSessionName=session_name, WebIdentityToken=token
            )
            return resp["Credentials"]
        except ClientError as exc:
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"assume_role_with_web_identity never succeeded (IAM propagation?): {last_err}")


def _client_error(fn):
    """Call fn(); return the ClientError's (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
