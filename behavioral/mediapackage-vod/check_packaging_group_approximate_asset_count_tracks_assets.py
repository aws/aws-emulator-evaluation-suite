"""packaging-group-approximate-asset-count-tracks-assets."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "packaging-group-approximate-asset-count-tracks-assets"
GROUP = "derived-state"
SERVICES = ["mediapackage-vod"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A packaging group's ApproximateAssetCount, which no call sets directly, follows CreateAsset
    and DeleteAsset; DescribePackagingGroup and ListPackagingGroups agree on it, and a second
    group's count stays untouched.
    """
    mpv = ctx.client("mediapackage-vod")
    group_id = ctx.unique_name("sim2real-mpvod-count-")
    mpv.create_packaging_group(Id=group_id, Tags={"sim2real": CHECK})
    ctx.on_cleanup(_teardown(lambda: mpv.delete_packaging_group(Id=group_id), "NotFoundException"))
    other_id = ctx.unique_name("sim2real-mpvod-other-")
    mpv.create_packaging_group(Id=other_id, Tags={"sim2real": CHECK})
    ctx.on_cleanup(_teardown(lambda: mpv.delete_packaging_group(Id=other_id), "NotFoundException"))

    initial = mpv.describe_packaging_group(Id=group_id)["ApproximateAssetCount"]
    assert initial == 0, f"a new packaging group reported ApproximateAssetCount {initial!r}, expected 0"

    src = _create_source(ctx)
    asset_ids = [ctx.unique_name("sim2real-mpvod-asset-") for _ in range(2)]
    for asset_id in asset_ids:
        _create_asset(
            ctx,
            mpv,
            Id=asset_id,
            PackagingGroupId=group_id,
            SourceArn=src["source_arn"],
            SourceRoleArn=src["role_arn"],
            Tags={"sim2real": CHECK},
        )
        ctx.on_cleanup(_teardown(lambda a=asset_id: mpv.delete_asset(Id=a), "NotFoundException"))

    described, listed = _converge(mpv, group_id, 2)
    assert (described, listed) == (2, 2), (
        f"after two CreateAsset calls DescribePackagingGroup reported {described!r} and "
        f"ListPackagingGroups {listed!r}; expected both 2"
    )

    mpv.delete_asset(Id=asset_ids[1])
    gone = _wait_asset_gone(mpv, asset_ids[1])
    assert gone == f"Asset with id={asset_ids[1]} not found", f"deleted asset read back as {gone!r}"

    described, listed = _converge(mpv, group_id, 1)
    assert (described, listed) == (1, 1), (
        f"after deleting one of two assets DescribePackagingGroup reported {described!r} and "
        f"ListPackagingGroups {listed!r}; expected both 1"
    )

    other = mpv.describe_packaging_group(Id=other_id)["ApproximateAssetCount"]
    assert other == 0, f"a group no asset was ingested into reported ApproximateAssetCount {other!r}"
    other_listed = _listed_count(mpv, other_id)
    assert other_listed == 0, f"ListPackagingGroups reported {other_listed!r} assets for the empty group"


def _listed_count(mpv, group_id: str):
    """The ApproximateAssetCount ListPackagingGroups reports for ``group_id``, across every page."""
    for page in mpv.get_paginator("list_packaging_groups").paginate():
        for group in page["PackagingGroups"]:
            if group["Id"] == group_id:
                return group.get("ApproximateAssetCount")
    raise AssertionError(f"packaging group {group_id} is missing from ListPackagingGroups")


def _converge(mpv, group_id: str, want: int, timeout_s: float = 120.0):
    """Poll until Describe and List both report ``want`` (the count is approximate), or time out.

    Returns the last (describe, list) pair, so the caller's assertion quotes what was observed.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        described = mpv.describe_packaging_group(Id=group_id).get("ApproximateAssetCount")
        listed = _listed_count(mpv, group_id)
        if (described, listed) == (want, want) or time.monotonic() > deadline:
            return described, listed
        time.sleep(3.0)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_source(ctx) -> dict[str, str]:
    """A bucket holding a one-line SMIL manifest and a role MediaPackage may assume to read it.

    The groups in this check carry no packaging configuration, so the asset is never packaged and
    the manifest's content is never fetched; CreateAsset only validates that the object and role
    are usable.
    """
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    bucket = ctx.unique_name("sim2real-mpvod-src-")
    # us-east-1 is the one region S3 rejects an explicit LocationConstraint for; a transport quirk
    # of CreateBucket, not a pinned region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=bucket), "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    key = "asset/asset.smil"
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=b'<?xml version="1.0" encoding="utf-8"?>\n<smil><body><switch>'
        b'<video name="video.mp4"/></switch></body></smil>\n',
    )
    ctx.on_cleanup(_teardown(lambda: s3.delete_object(Bucket=bucket, Key=key), "NoSuchBucket"))

    role_name = ctx.unique_name("sim2real-mpvod-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "mediapackage.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    # The four actions MediaPackage's S3 access policy for VOD workflows requires, on the bucket
    # and its objects; CreateAsset validates them synchronously.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="source-access",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                            "s3:GetBucketLocation",
                            "s3:GetBucketRequestPayment",
                            "s3:ListBucket",
                        ],
                        "Resource": [f"arn:aws:s3:::{bucket}/*", f"arn:aws:s3:::{bucket}"],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        _teardown(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="source-access"), "NoSuchEntity")
    )
    return {"source_arn": f"arn:aws:s3:::{bucket}/{key}", "role_arn": role_arn}


def _create_asset(ctx, mpv, timeout_s: float = 90.0, **kwargs):
    """CreateAsset, retried while IAM has not yet propagated the new role's trust policy.

    No API reports that a role has become assumable, so the first use is retried on the two
    refusals that propagation lag produces, for a bounded window.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return mpv.create_asset(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            lag = code == "ForbiddenException" or (
                code == "UnprocessableEntityException" and ("assumable" in msg or "fetchable" in msg)
            )
            if not lag or time.monotonic() > deadline:
                raise
            time.sleep(3.0)


def _wait_asset_gone(mpv, asset_id: str, timeout_s: float = 60.0) -> str:
    """DescribeAsset until NotFoundException and return its message; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            mpv.describe_asset(Id=asset_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return e.response["Error"]["Message"]
            raise
        if time.monotonic() > deadline:
            raise AssertionError(f"asset {asset_id} was still describable {timeout_s}s after DeleteAsset")
        time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
