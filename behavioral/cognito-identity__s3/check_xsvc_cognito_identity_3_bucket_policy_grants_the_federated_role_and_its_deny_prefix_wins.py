"""xsvc-cognito-identity-3-bucket-policy-grants-the-federated-role-and-its-deny-prefix-wins."""
from __future__ import annotations

import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cognito-identity-3-bucket-policy-grants-the-federated-role-and-its-deny-prefix-wins"
GROUP = "downstream-principal"
SERVICES = ["cognito-identity", "s3"]

_DENIED_CODE = "AccessDenied"
_PROPAGATION_BUDGET_S = 120.0


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


def _read(s3, bucket, key):
    """GetObject; return (body, None) or (None, Code). Hard-subscripted on purpose."""
    try:
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read(), None
    except ClientError as exc:
        return None, exc.response.get("Error", {}).get("Code")


def _poll_read(make_client, bucket, key, predicate, *, timeout_s, description):
    """Poll a read until predicate((body, code)) holds; returns (result, client).

    Bucket-policy changes are eventually consistent per S3 front end and a keep-alive connection
    can pin a stale one, so each attempt builds a fresh client from the same credentials."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        client = make_client()
        last = _read(client, bucket, key)
        if predicate(last):
            return last, client
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not observed within {timeout_s}s; last={last!r}")
        time.sleep(3.0)


def _delete_role(iam, role_name):
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _empty_and_delete_bucket(s3, bucket):
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})
    s3.delete_bucket(Bucket=bucket)


def _client_from_credentials(ctx, service, creds):
    """A NEW target client signed with vended temporary credentials, handed over by value.

    The unique user-agent suffix gives every call its own client and so its own connection, which
    ``_poll_read`` needs to leave a stale S3 front end.
    """
    return ctx.client(
        service,
        config=Config(retries={"max_attempts": 2},
                      user_agent_extra=f"sim2real-conn-{uuid.uuid4().hex[:8]}"),
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds.get("SecretKey") or creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _bucket_policy(bucket, role_arn, *, allow_all, deny_prefix):
    statements = []
    if allow_all:
        statements.append({
            "Sid": "AllowFederatedRoleReadWholeBucket",
            "Effect": "Allow",
            "Principal": {"AWS": role_arn},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
        })
    if deny_prefix:
        statements.append({
            "Sid": "DenyFederatedRoleTheRestrictedPrefix",
            "Effect": "Deny",
            "Principal": {"AWS": role_arn},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/restricted/*",
        })
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A bucket policy allowing the federated role lets a vended session read granted/, its explicit
    Deny on restricted/ beats both the bucket and role allows (AccessDenied); dropping the Deny
    admits restricted/, and keeping only the Deny makes granted/ AccessDenied.
    """
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    # ---- bucket and two objects.
    bucket = ctx.unique_name("sim2real-xsvc-ci3-")[:63].lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "xsvc-cognito-identity-3"}]})
    granted_key, restricted_key = "granted/report.txt", "restricted/secret.txt"
    granted_body = b"granted-" + uuid.uuid4().bytes
    restricted_body = b"restricted-" + uuid.uuid4().bytes
    s3.put_object(Bucket=bucket, Key=granted_key, Body=granted_body)
    s3.put_object(Bucket=bucket, Key=restricted_key, Body=restricted_body)

    # ---- identity pool, guest identity, and the federated role.
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_xsvc_ci3_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": "xsvc-cognito-identity-3"},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    role_name = ctx.unique_name("sim2real-xsvc-ci3-guest-")[:64]
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "unauthenticated"},
                },
            }],
        }),
        Tags=[{"Key": "sim2real", "Value": "xsvc-cognito-identity-3"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    # The role's OWN policy grants the restricted prefix only — never granted/.
    iam.put_role_policy(
        RoleName=role_name, PolicyName="read-restricted-prefix-only",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                           "Resource": f"arn:aws:s3:::{bucket}/restricted/*"}],
        }),
    )
    _retry(lambda: ci.set_identity_pool_roles(IdentityPoolId=pool_id,
                                              Roles={"unauthenticated": role_arn}),
           retryable={"InvalidParameterException", "AccessDeniedException"},
           timeout_s=_PROPAGATION_BUDGET_S, description="SetIdentityPoolRoles")

    # Bucket policy: Allow the role on bucket/*, Deny it restricted/*. A just-created role can be
    # rejected as an invalid principal until IAM propagates, so that one code is retried.
    _retry(lambda: s3.put_bucket_policy(
        Bucket=bucket,
        Policy=_bucket_policy(bucket, role_arn, allow_all=True, deny_prefix=True)),
        retryable={"MalformedPolicy"}, timeout_s=_PROPAGATION_BUDGET_S,
        description="PutBucketPolicy naming the federated role")
    ctx.on_cleanup(lambda: s3.delete_bucket_policy(Bucket=bucket))

    identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))
    def _vend():
        return _retry(lambda: ci.get_credentials_for_identity(IdentityId=identity_id),
                      retryable={"InvalidIdentityPoolConfigurationException", "AccessDenied",
                                 "NotAuthorizedException"},
                      timeout_s=_PROPAGATION_BUDGET_S,
                      description="GetCredentialsForIdentity")["Credentials"]

    # ---- positive control: granted/ is readable, and ONLY the bucket policy grants it.
    # A session minted inside the new role's IAM propagation window can stay AccessDenied, so each
    # attempt vends a FRESH session, and the one that finally reads is used by every later leg.
    # This waits on propagation only; once a read succeeds no further denial is retried.
    started = time.monotonic()
    deadline = started + 2 * _PROPAGATION_BUDGET_S
    last = None
    while True:
        vended = _vend()
        vs3 = _client_from_credentials(ctx, "s3", vended)
        last = _read(vs3, bucket, granted_key)
        if last[0] is not None or time.monotonic() >= deadline:
            break
        time.sleep(5.0)
    body, code = last
    assert body == granted_body, (
        f"granted/ read by the federated role (granted only by the bucket policy) returned "
        f"{body!r} / {code!r} after {time.monotonic() - started:.0f}s; expected {granted_body!r}"
    )
    print(f"[measure] bucket-policy grant readable after {time.monotonic() - started:.1f}s")
    who = _client_from_credentials(ctx, "sts", vended).get_caller_identity()["Arn"]
    assert f":assumed-role/{role_name}/" in who, (
        f"the vended session is {who!r}, not a session of the mapped role {role_name!r}"
    )

    # ---- negative: restricted/ is allowed by the role AND the bucket, and denied by the bucket.
    # Before the bucket policy existed the role's own Allow admitted restricted/, so a front end
    # that has not yet seen the policy could still serve it: poll for the Deny, never read once.
    (body, code), vs3 = _poll_read(lambda: _client_from_credentials(ctx, "s3", vended), bucket,
                                   restricted_key, lambda r: r[0] is None,
                                   timeout_s=_PROPAGATION_BUDGET_S,
                                   description="restricted/ to be refused under the explicit Deny")
    assert body is None, (
        f"restricted/ was READ ({body!r}) although the bucket policy explicitly Denies it; the "
        f"two Allows must not override an explicit Deny"
    )
    assert code == _DENIED_CODE, (
        f"restricted/ read under an explicit bucket-policy Deny returned {code!r}, expected "
        f"{_DENIED_CODE!r}"
    )

    # ---- repair the one thing: drop the Deny, and the SAME session reads restricted/.
    s3.put_bucket_policy(Bucket=bucket,
                         Policy=_bucket_policy(bucket, role_arn, allow_all=True, deny_prefix=False))
    (body, code), vs3 = _poll_read(lambda: _client_from_credentials(ctx, "s3", vended), bucket,
                                   restricted_key, lambda r: r[0] is not None,
                                   timeout_s=_PROPAGATION_BUDGET_S,
                                   description="restricted/ to become readable once the Deny "
                                               "is removed")
    assert body == restricted_body, (
        f"restricted/ read after removing the Deny returned {body!r}, expected {restricted_body!r}"
    )

    # ---- and the bucket Allow is load-bearing: keep only the Deny, granted/ becomes AccessDenied
    # because the role's identity policy never granted it.
    s3.put_bucket_policy(Bucket=bucket,
                         Policy=_bucket_policy(bucket, role_arn, allow_all=False, deny_prefix=True))
    (body, code), vs3 = _poll_read(lambda: _client_from_credentials(ctx, "s3", vended), bucket,
                                   granted_key, lambda r: r[0] is None,
                                   timeout_s=_PROPAGATION_BUDGET_S,
                                   description="granted/ to stop being readable once the "
                                               "bucket Allow is removed")
    assert code == _DENIED_CODE, (
        f"granted/ read with no bucket Allow (and no identity Allow) returned {code!r}, expected "
        f"{_DENIED_CODE!r}"
    )
    # The previous policy ALLOWED restricted/, so a stale front end may still serve it: poll for the
    # reinstated Deny to land rather than reading once. A target that never denies fails here.
    (body, code), vs3 = _poll_read(lambda: _client_from_credentials(ctx, "s3", vended), bucket,
                                   restricted_key, lambda r: r[0] is None,
                                   timeout_s=_PROPAGATION_BUDGET_S,
                                   description="restricted/ to be refused under the reinstated "
                                               "Deny")
    assert code == _DENIED_CODE, (
        f"restricted/ read under the reinstated Deny (identity policy still allows it) returned "
        f"{code!r} with body {body!r}, expected {_DENIED_CODE!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
