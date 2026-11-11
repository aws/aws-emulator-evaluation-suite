"""list-assets-filtered-by-packaging-group."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-assets-filtered-by-packaging-group"
GROUP = "state"
SERVICES = ["mediapackage-vod"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAssets with a PackagingGroupId filter returns only that group's assets, not assets that
    belong to a sibling packaging group."""
    mpv = ctx.client("mediapackage-vod")
    src = _create_source_bucket_and_role(ctx)

    group_a = ctx.unique_name("sim2real-mpvod-groupa-")
    group_b = ctx.unique_name("sim2real-mpvod-groupb-")
    mpv.create_packaging_group(Id=group_a, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mpv.delete_packaging_group(Id=group_a))
    mpv.create_packaging_group(Id=group_b, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mpv.delete_packaging_group(Id=group_b))

    asset_a = ctx.unique_name("sim2real-mpvod-asseta-")
    _create_asset_with_retry(
        ctx, mpv, Id=asset_a, PackagingGroupId=group_a,
        SourceArn=src["source_arn"], SourceRoleArn=src["role_arn"],
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: mpv.delete_asset(Id=asset_a))

    asset_b = ctx.unique_name("sim2real-mpvod-assetb-")
    _create_asset_with_retry(
        ctx, mpv, Id=asset_b, PackagingGroupId=group_b,
        SourceArn=src["source_arn"], SourceRoleArn=src["role_arn"],
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: mpv.delete_asset(Id=asset_b))

    filtered_ids = {a["Id"] for a in mpv.list_assets(PackagingGroupId=group_a)["Assets"]}
    assert asset_a in filtered_ids, f"expected {asset_a} (group {group_a}) in filtered ids, got {filtered_ids}"
    assert asset_b not in filtered_ids, f"expected {asset_b} (group {group_b}) absent from filtered ids, got {filtered_ids}"


def _create_source_bucket_and_role(ctx) -> dict[str, str]:
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    bucket = ctx.unique_name("sim2real-mpvod-src-")
    # us-east-1 rejects an explicit LocationConstraint on CreateBucket; every other region requires one.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
