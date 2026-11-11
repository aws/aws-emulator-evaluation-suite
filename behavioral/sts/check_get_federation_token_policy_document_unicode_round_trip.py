"""get-federation-token-policy-document-unicode-round-trip."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-federation-token-policy-document-unicode-round-trip"
GROUP = "representation"
SERVICES = ["sts"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A GetFederationToken session-policy Deny on an S3 object key with accented Latin and CJK
    characters blocks GetObject on that exact key and leaves a sibling ASCII key readable, so the
    unicode Resource ARN survives the policy round trip byte-exact."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    s3 = ctx.client("s3")
    region = ctx.region

    bucket_name = ctx.unique_name("sim2real-behav-fedpolkey-")
    _create_bucket(s3, bucket_name, region)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )

    unicode_key = "café/日本語/Zürich-résumé.txt"
    ascii_key = "plain/other.txt"
    s3.put_object(Bucket=bucket_name, Key=unicode_key, Body=b"unicode-target")
    s3.put_object(Bucket=bucket_name, Key=ascii_key, Body=b"ascii-target")

    user_name = ctx.unique_name("sim2real-behav-fedpol-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    base_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["sts:GetFederationToken", "s3:GetObject"],
                "Resource": "*",
            }
        ],
    }
    policy_name = "sim2real-behav-fedpol-policy"
    iam.put_user_policy(
        UserName=user_name, PolicyName=policy_name, PolicyDocument=json.dumps(base_policy)
    )
    ctx.on_cleanup(
        lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
    )

    access_key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(
            UserName=user_name, AccessKeyId=access_key["AccessKeyId"]
        )
    )
    user_creds = {
        "AccessKeyId": access_key["AccessKeyId"],
        "SecretAccessKey": access_key["SecretAccessKey"],
    }
    base_client = _client_with_creds(ctx, "sts", user_creds)
    _wait_for_new_credentials(base_client)

    # Sid values must be plain alphanumeric (MalformedPolicyDocument), so the unicode under test
    # lives in the Resource ARN's object-key segment.
    unicode_resource_arn = f"arn:aws:s3:::{bucket_name}/{unicode_key}"
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowGetObject",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
            },
            {
                "Sid": "DenyExactUnicodeKey",
                "Effect": "Deny",
                "Action": "s3:GetObject",
                "Resource": unicode_resource_arn,
            },
        ],
    }
    federation = base_client.get_federation_token(
        Name=ctx.unique_name("fedpolkey-")[:32], Policy=json.dumps(deny_policy)
    )
    scoped_creds = federation["Credentials"]
    federated_arn = federation["FederatedUser"]["Arn"]
    scoped_s3 = _client_with_creds(ctx, "s3", scoped_creds)

    error = _client_error(lambda: scoped_s3.get_object(Bucket=bucket_name, Key=unicode_key))
    assert error == (
        "AccessDenied",
        f"User: {federated_arn} is not authorized to perform: s3:GetObject on resource: "
        f'"{unicode_resource_arn}" with an explicit deny in a session policy',
    ), (
        f"expected AccessDenied on GetObject({unicode_key!r}) via the unicode-scoped "
        f"Deny (independent scoped-credentials S3 client), got {error!r}"
    )

    # The sibling key stays readable: the Deny did not degrade to a wildcard match.
    body = scoped_s3.get_object(Bucket=bucket_name, Key=ascii_key)["Body"].read()
    assert body == b"ascii-target", (
        f"expected sibling ASCII-keyed object {ascii_key!r} to remain readable and "
        f"unaffected by the unicode-scoped Deny, got body {body!r}"
    )


def _create_bucket(s3_client, bucket_name: str, region: str) -> None:
    if region == "us-east-1":
        s3_client.create_bucket(Bucket=bucket_name)
    else:
        s3_client.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region}
        )


def _empty_and_delete_bucket(s3_client, bucket_name: str) -> None:
    paginator = s3_client.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket_name):
        objects = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        if objects:
            failed = s3_client.delete_objects(Bucket=bucket_name, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3_client.delete_bucket(Bucket=bucket_name)


def _client_with_creds(ctx, service: str, creds: dict[str, Any]):
    override = {
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
    }
    if creds.get("SessionToken"):
        override["aws_session_token"] = creds["SessionToken"]
    return ctx.client(service, creds=override)


def _wait_for_new_credentials(sts_client, timeout_s: float = 30.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            sts_client.get_caller_identity()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in ("InvalidClientTokenId", "AccessDenied"):
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"new access key never became active within {timeout_s}s: {last_err}")


def _client_error(fn):
    """Call fn() and return its botocore error (code, message); an unexpected success raises
    rather than surfacing as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be denied, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
