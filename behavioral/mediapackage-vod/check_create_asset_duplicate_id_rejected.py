"""create-asset-duplicate-id-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-asset-duplicate-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackage-vod"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAsset with an Id that already exists is rejected with UnprocessableEntityException,
    the original asset's SourceArn is left untouched, and a differently-Id'd asset still succeeds
    (positive control)."""
    mpv = ctx.client("mediapackage-vod")
    group_id = ctx.unique_name("sim2real-mpvod-group-")
    mpv.create_packaging_group(Id=group_id, Tags={"env": "sim2real", "owner": "behavioral-suite"})
    ctx.on_cleanup(lambda: mpv.delete_packaging_group(Id=group_id))

    src = _create_source_bucket_and_role(ctx)
    asset_id = ctx.unique_name("sim2real-mpvod-asset-")
    _create_asset_with_retry(
        ctx, mpv, Id=asset_id, PackagingGroupId=group_id,
        SourceArn=src["source_arn"], SourceRoleArn=src["role_arn"],
        Tags={"env": "sim2real", "owner": "behavioral-suite"},
    )
    ctx.on_cleanup(lambda: mpv.delete_asset(Id=asset_id))

    other_key = "source/other.m3u8"
    s3 = ctx.client("s3")
    s3.put_object(Bucket=src["bucket"], Key=other_key, Body=b"different-placeholder-bytes")
    other_source_arn = f"arn:aws:s3:::{src['bucket']}/{other_key}"

    code, message = _error(
        lambda: mpv.create_asset(
            Id=asset_id,
            PackagingGroupId=group_id,
            SourceArn=other_source_arn,
            SourceRoleArn=src["role_arn"],
        )
    )
    assert code == "UnprocessableEntityException", (
        f"expected UnprocessableEntityException on duplicate Id, got {code!r}"
    )
    expected_message = f"Asset with id={asset_id} already exists"
    assert message == expected_message, (
        f"expected message {expected_message!r} on duplicate Id, got {message!r}"
    )

    # Effect absent: the original asset's SourceArn was not overwritten.
    described = mpv.describe_asset(Id=asset_id)
    assert described["SourceArn"] == src["source_arn"], (
        f"expected original SourceArn {src['source_arn']!r}, got {described['SourceArn']!r}"
    )
    assert described["SourceArn"] != other_source_arn, (
        "duplicate-Id create must not overwrite the original asset's SourceArn"
    )

    # Positive control: a distinct Id in the same group succeeds, and the effect is
    # visible through an independent read (describe_asset), not just the create response.
    other_asset_id = ctx.unique_name("sim2real-mpvod-asset2-")
    created_other = _create_asset_with_retry(
        ctx, mpv, Id=other_asset_id, PackagingGroupId=group_id,
        SourceArn=other_source_arn, SourceRoleArn=src["role_arn"],
        Tags={"env": "sim2real", "owner": "behavioral-suite"},
    )
    ctx.on_cleanup(lambda: mpv.delete_asset(Id=other_asset_id))
    assert created_other["Id"] == other_asset_id, (
        f"expected create_asset to echo Id {other_asset_id!r}, got {created_other['Id']!r}"
    )

    described_other = mpv.describe_asset(Id=other_asset_id)
    assert described_other["SourceArn"] == other_source_arn, (
        f"expected distinct-Id asset to carry SourceArn {other_source_arn!r}, "
        f"got {described_other['SourceArn']!r}"
    )


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_source_bucket_and_role(ctx) -> dict[str, str]:
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    bucket = ctx.unique_name("sim2real-mpvod-src-")
    # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1; this branches on
    # ctx.region, it does not assume one.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
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
