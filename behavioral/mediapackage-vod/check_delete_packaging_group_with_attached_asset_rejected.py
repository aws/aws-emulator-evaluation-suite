"""delete-packaging-group-with-attached-asset-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-packaging-group-with-attached-asset-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackage-vod"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePackagingGroup is refused while an asset is attached, even with no packaging
    configuration: the refusal names attached assets, the group and asset both survive, and once the
    asset is deleted the same delete succeeds.
    """
    mpv = ctx.client("mediapackage-vod")
    group_id = ctx.unique_name("sim2real-mpvod-held-")
    mpv.create_packaging_group(Id=group_id, Tags={"sim2real": CHECK})
    ctx.on_cleanup(_teardown(lambda: mpv.delete_packaging_group(Id=group_id), "NotFoundException"))

    src = _create_source(ctx)
    asset_id = ctx.unique_name("sim2real-mpvod-asset-")
    _create_asset(
        ctx,
        mpv,
        Id=asset_id,
        PackagingGroupId=group_id,
        SourceArn=src["source_arn"],
        SourceRoleArn=src["role_arn"],
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(_teardown(lambda: mpv.delete_asset(Id=asset_id), "NotFoundException"))

    code, message = _error(lambda: mpv.delete_packaging_group(Id=group_id))
    assert code == "UnprocessableEntityException", (
        f"DeletePackagingGroup with an attached asset raised {code!r}, expected UnprocessableEntityException"
    )
    assert message == "id cannot be deleted because it has attached assets", (
        f"DeletePackagingGroup with an attached asset said {message!r}"
    )

    still = mpv.describe_packaging_group(Id=group_id)
    assert still["Id"] == group_id, f"the refused delete left group {still.get('Id')!r}, expected {group_id!r}"
    asset = mpv.describe_asset(Id=asset_id)
    assert asset["PackagingGroupId"] == group_id, (
        f"the attached asset now names packaging group {asset.get('PackagingGroupId')!r}, expected {group_id!r}"
    )

    # Positive control: with the asset gone the same delete goes through.
    mpv.delete_asset(Id=asset_id)
    _wait_asset_gone(mpv, asset_id)
    _delete_group_when_released(mpv, group_id)
    gone = _wait_group_gone(mpv, group_id)
    assert gone == f"PackagingGroup with id={group_id} not found", (
        f"after the delete DescribePackagingGroup said {gone!r}"
    )


def _wait_group_gone(mpv, group_id: str, timeout_s: float = 60.0) -> str:
    """DescribePackagingGroup until NotFoundException and return its message; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            mpv.describe_packaging_group(Id=group_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return e.response["Error"]["Message"]
            raise
        if time.monotonic() > deadline:
            raise AssertionError(f"group {group_id} was still describable {timeout_s}s after its delete")
        time.sleep(2.0)


def _delete_group_when_released(mpv, group_id: str, timeout_s: float = 60.0) -> None:
    """DeletePackagingGroup, retried while the deleted asset's attachment is still being released."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            mpv.delete_packaging_group(Id=group_id)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "UnprocessableEntityException" or time.monotonic() > deadline:
                raise
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
