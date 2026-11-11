"""create-asset-nonexistent-packaging-group-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-asset-nonexistent-packaging-group-not-found"
GROUP = "error-semantics"
SERVICES = ["mediapackage-vod"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAsset against a PackagingGroupId that does not exist is rejected with
    UnprocessableEntityException and creates no asset (positive control: the same source/role
    succeeds against a real group and yields the expected egress endpoint)."""
    mpv = ctx.client("mediapackage-vod")
    src = _create_source_bucket_and_role(ctx)

    bogus_group_id = ctx.unique_name("sim2real-mpvod-nogroup-")
    asset_id = ctx.unique_name("sim2real-mpvod-asset-")
    code, message = _error_with_retry(
        lambda: mpv.create_asset(
            Id=asset_id,
            PackagingGroupId=bogus_group_id,
            SourceArn=src["source_arn"],
            SourceRoleArn=src["role_arn"],
        )
    )
    assert code == "UnprocessableEntityException", f"expected UnprocessableEntityException, got {code}"
    assert message == "packaging_group_id does not exist", (
        f"expected message 'packaging_group_id does not exist', got {message!r}"
    )

    # Effect absent: the asset was never created.
    absent_code, absent_message = _error(lambda: mpv.describe_asset(Id=asset_id))
    assert absent_code == "NotFoundException", f"expected NotFoundException, got {absent_code}"
    expected_absent = f"Asset with id={asset_id} not found"
    assert absent_message == expected_absent, (
        f"expected message {expected_absent!r}, got {absent_message!r}"
    )

    # Positive control: the identical request against a real group (with a packaging
    # configuration attached) succeeds and yields an egress endpoint.
    real_group_id = ctx.unique_name("sim2real-mpvod-group-")
    mpv.create_packaging_group(
        Id=real_group_id, Tags={"sim2real-check": CHECK}
    )
    ctx.on_cleanup(lambda: mpv.delete_packaging_group(Id=real_group_id))
    hls_id = ctx.unique_name("sim2real-mpvod-hls-")
    mpv.create_packaging_configuration(
        Id=hls_id,
        PackagingGroupId=real_group_id,
        HlsPackage={"HlsManifests": [{"ManifestName": "index"}]},
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: mpv.delete_packaging_configuration(Id=hls_id))
    created = _create_asset_with_retry(
        ctx,
        mpv,
        Id=asset_id,
        PackagingGroupId=real_group_id,
        SourceArn=src["source_arn"],
        SourceRoleArn=src["role_arn"],
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: mpv.delete_asset(Id=asset_id))
    assert created["Id"] == asset_id, f"expected Id {asset_id}, got {created.get('Id')}"

    # Independent read: the terminal assertion is on DescribeAsset, not the CreateAsset
    # response, so a target that echoes the request without actually provisioning the
    # egress endpoint cannot pass.
    described_real = mpv.describe_asset(Id=asset_id)
    assert described_real["Id"] == asset_id, (
        f"expected DescribeAsset to return Id {asset_id}, got {described_real.get('Id')}"
    )
    endpoints = described_real["EgressEndpoints"]
    assert len(endpoints) == 1, f"expected exactly 1 egress endpoint, got {len(endpoints)}"


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _error_with_retry(fn, timeout_s: float = 90.0):
    """Same as _error, but treats the transient role-assumability/bucket-fetchability
    validation shapes (surfaced while a just-created role's IAM permissions are still
    propagating) as retryable rather than as the final answer."""
    deadline = time.monotonic() + timeout_s
    while True:
        code, msg = _error(fn)
        transient = code == "ForbiddenException" or (
            code == "UnprocessableEntityException"
            and ("assumable" in (msg or "").lower() or "fetchable" in (msg or "").lower())
        )
        if not transient or time.monotonic() >= deadline:
            return code, msg
        time.sleep(3.0)


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
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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

