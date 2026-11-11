"""delete-asset-state-transition."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-asset-state-transition"
GROUP = "state"
SERVICES = ["mediapackage-vod"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAsset returns 204 No Content and the asset transitions to gone asynchronously: it may
    still be describable for a short window but eventually resolves to NotFoundException. Once
    gone, a second mutation on the same id also fails not-found, and the id is reusable."""
    mpv = ctx.client("mediapackage-vod")
    group_id = ctx.unique_name("sim2real-mpvod-group-")
    mpv.create_packaging_group(Id=group_id, Tags={"env": "sim2real"})
    ctx.on_cleanup(lambda: mpv.delete_packaging_group(Id=group_id))

    src = _create_source_bucket_and_role(ctx)
    asset_id = ctx.unique_name("sim2real-mpvod-asset-")
    _create_asset_with_retry(
        ctx, mpv, Id=asset_id, PackagingGroupId=group_id,
        SourceArn=src["source_arn"], SourceRoleArn=src["role_arn"],
        Tags={"env": "sim2real"},
    )
    ctx.on_cleanup(lambda: _best_effort_delete_asset(mpv, asset_id))

    resp = mpv.delete_asset(Id=asset_id)
    status_code = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status_code == 204, f"expected 204 No Content, got {status_code}"

    expected_not_found = f"Asset with id={asset_id} not found"
    gone_message = _poll_until_asset_not_found(ctx, asset_id, timeout_s=60.0)
    assert gone_message == expected_not_found, (
        f"expected DescribeAsset message {expected_not_found!r}, got {gone_message!r}"
    )

    # The dead id is not just unreadable: a second mutation on it also fails not-found.
    redelete_code, redelete_message = _error(lambda: mpv.delete_asset(Id=asset_id))
    assert redelete_code == "NotFoundException", (
        f"expected NotFoundException re-deleting gone asset {asset_id}, got {redelete_code}"
    )
    assert redelete_message == expected_not_found, (
        f"expected re-delete message {expected_not_found!r}, got {redelete_message!r}"
    )

    # The id is reusable once the prior asset has fully resolved to gone.
    recreated = _create_asset_with_retry(
        ctx, mpv, Id=asset_id, PackagingGroupId=group_id,
        SourceArn=src["source_arn"], SourceRoleArn=src["role_arn"],
        Tags={"env": "sim2real"},
    )
    assert recreated["Id"] == asset_id, (
        f"expected asset id {asset_id} to be reusable after the prior asset resolved gone, "
        f"got {recreated.get('Id')!r}"
    )
    described = mpv.describe_asset(Id=asset_id)
    assert described["Id"] == asset_id, f"expected recreated asset {asset_id} to describe, got {described}"


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _best_effort_delete_asset(mpv, asset_id: str) -> None:
    try:
        mpv.delete_asset(Id=asset_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


def _poll_until_asset_not_found(ctx, asset_id: str, timeout_s: float = 60.0) -> str:
    """Describe until NotFoundException and return its message; raise on timeout."""
    mpv = ctx.client("mediapackage-vod")
    deadline = time.monotonic() + timeout_s
    code = None
    while time.monotonic() < deadline:
        try:
            mpv.describe_asset(Id=asset_id)
            code = None
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NotFoundException":
                return e.response["Error"].get("Message")
        time.sleep(2.0)
    raise AssertionError(
        f"asset {asset_id} did not become NotFoundException within {timeout_s}s "
        f"(last observed code: {code})"
    )


def _create_source_bucket_and_role(ctx) -> dict[str, str]:
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    bucket = ctx.unique_name("sim2real-mpvod-src-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "env", "Value": "sim2real"}]})
    key = "source/asset.m3u8"
    s3.put_object(Bucket=bucket, Key=key, Body=b"placeholder-source-bytes")
    source_arn = f"arn:aws:s3:::{bucket}/{key}"

    role_name = ctx.unique_name("sim2real-mpvod-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "mediapackage.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "env", "Value": "sim2real"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket}/*"},
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "s3:GetBucketLocation", "s3:GetBucketRequestPayment"],
                "Resource": f"arn:aws:s3:::{bucket}",
            },
        ],
    }
    policy_name = "source-access"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return {"bucket": bucket, "source_arn": source_arn, "role_arn": role_arn}


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _create_asset_with_retry(ctx, mpv, timeout_s: float = 90.0, **kwargs):
    """CreateAsset synchronously validates that SourceRoleArn is assumable by MediaPackage; a
    just-created role's trust policy can lag IAM's eventual consistency, surfacing as either
    ForbiddenException or an UnprocessableEntityException mentioning role assumability. Retry
    those transient shapes for a bounded window."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return mpv.create_asset(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code == "ForbiddenException" or (
                code == "UnprocessableEntityException"
                and ("assumable" in msg.lower() or "fetchable" in msg.lower())
            ):
                last_err = e
                time.sleep(3.0)
                continue
            raise
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
