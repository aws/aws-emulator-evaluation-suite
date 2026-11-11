"""asset-egress-endpoints-match-packaging-configurations."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asset-egress-endpoints-match-packaging-configurations"
GROUP = "state"
SERVICES = ["mediapackage-vod"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAsset returns exactly one EgressEndpoint per PackagingConfiguration in the group, each
    tagged with the right PackagingConfigurationId and a playable-manifest URL shape. The independent
    terminal read is DescribeAsset -- CreateAsset's own response is not trusted alone."""
    mpv = ctx.client("mediapackage-vod")
    check_tags = {"sim2real-check": CHECK}
    group_id = ctx.unique_name("sim2real-mpvod-group-")
    mpv.create_packaging_group(Id=group_id, Tags=check_tags)
    ctx.on_cleanup(lambda: mpv.delete_packaging_group(Id=group_id))

    hls_id = ctx.unique_name("sim2real-mpvod-hls-")
    mpv.create_packaging_configuration(
        Id=hls_id,
        PackagingGroupId=group_id,
        HlsPackage={"HlsManifests": [{"ManifestName": "index"}]},
        Tags=check_tags,
    )
    ctx.on_cleanup(lambda: mpv.delete_packaging_configuration(Id=hls_id))

    dash_id = ctx.unique_name("sim2real-mpvod-dash-")
    mpv.create_packaging_configuration(
        Id=dash_id,
        PackagingGroupId=group_id,
        DashPackage={"DashManifests": [{"ManifestName": "dash"}]},
        Tags=check_tags,
    )
    ctx.on_cleanup(lambda: mpv.delete_packaging_configuration(Id=dash_id))

    src = _create_source_bucket_and_role(ctx, check_tags)
    asset_id = ctx.unique_name("sim2real-mpvod-asset-")
    created = _create_asset_with_retry(
        ctx,
        mpv,
        Id=asset_id,
        PackagingGroupId=group_id,
        SourceArn=src["source_arn"],
        SourceRoleArn=src["role_arn"],
        Tags=check_tags,
    )
    ctx.on_cleanup(lambda: mpv.delete_asset(Id=asset_id))

    def _check_endpoints(endpoints, source: str) -> None:
        assert len(endpoints) == 2, f"{source}: expected 2 egress endpoints, got {len(endpoints)}"
        config_ids = {e["PackagingConfigurationId"] for e in endpoints}
        assert config_ids == {hls_id, dash_id}, (
            f"{source}: expected endpoint PackagingConfigurationIds {{{hls_id!r}, {dash_id!r}}}, "
            f"got {config_ids!r}"
        )
        for endpoint in endpoints:
            assert endpoint["Url"].startswith("https://"), (
                f"{source}: expected an https:// manifest URL, got {endpoint['Url']!r}"
            )

    _check_endpoints(created["EgressEndpoints"], source="CreateAsset response")

    described = mpv.describe_asset(Id=asset_id)
    _check_endpoints(described["EgressEndpoints"], source="independent DescribeAsset read")


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


def _create_source_bucket_and_role(ctx, check_tags: dict[str, str]) -> dict[str, str]:
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
        Bucket=bucket, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in check_tags.items()]}
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
        Tags=[{"Key": k, "Value": v} for k, v in check_tags.items()],
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
