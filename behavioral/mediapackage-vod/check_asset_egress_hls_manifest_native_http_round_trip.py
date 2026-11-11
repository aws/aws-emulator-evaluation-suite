"""asset-egress-hls-manifest-native-http-round-trip."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asset-egress-hls-manifest-native-http-round-trip"
GROUP = "native-protocol"
SERVICES = ["mediapackage-vod"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An ffmpeg-encoded MP4 ingested as a MediaPackage VOD asset becomes PLAYABLE on its HLS endpoint, and
    an HTTPS GET of that endpoint's manifest URL answers 200 with an #EXTM3U playlist: the packaging
    pipeline actually runs."""
    from fidelity_tests_runner import require_tools

    require_tools("ffmpeg")

    mpv = ctx.client("mediapackage-vod")
    group_id = ctx.unique_name("sim2real-mpvod-group-")
    mpv.create_packaging_group(Id=group_id, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mpv.delete_packaging_group(Id=group_id))

    hls_id = ctx.unique_name("sim2real-mpvod-hls-")
    mpv.create_packaging_configuration(
        Id=hls_id,
        PackagingGroupId=group_id,
        HlsPackage={"HlsManifests": [{"ManifestName": "index"}], "SegmentDurationSeconds": 2},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: mpv.delete_packaging_configuration(Id=hls_id))

    src = _create_smil_source(ctx)

    asset_id = ctx.unique_name("sim2real-mpvod-asset-")
    _create_asset_with_retry(
        ctx,
        mpv,
        Id=asset_id,
        PackagingGroupId=group_id,
        SourceArn=src["source_arn"],
        SourceRoleArn=src["role_arn"],
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: mpv.delete_asset(Id=asset_id))

    endpoint = _poll_until_playable(ctx, asset_id, hls_id, timeout_s=600.0)
    manifest_url = endpoint["Url"]

    body, status = _http_get(ctx, manifest_url)
    assert status == 200, f"GET {manifest_url} returned HTTP {status}"
    assert body.lstrip().startswith("#EXTM3U"), (
        f"egress endpoint did not return a real HLS playlist; got: {body[:200]!r}"
    )


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


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


def _create_smil_source(ctx) -> dict[str, str]:
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-mpvod-src-")
    # us-east-1 is the one region S3 rejects an explicit LocationConstraint for; this is a
    # transport quirk of CreateBucket, not a pinned target region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    tmpdir = tempfile.mkdtemp(prefix="sim2real-mpvod-")
    mp4_path = os.path.join(tmpdir, "video.mp4")
    subprocess.run(
        [
            "ffmpeg", "-y", "-f", "lavfi", "-i", "testsrc=size=320x240:rate=15:duration=4",
            "-c:v", "libx264", "-pix_fmt", "yuv420p", "-profile:v", "baseline",
            "-movflags", "+faststart", mp4_path,
        ],
        check=True,
        capture_output=True,
    )
    smil_xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<smil><body><switch>"
        '<video name="video.mp4"/>'
        "</switch></body></smil>\n"
    )

    prefix = "asset"
    mp4_key = f"{prefix}/video.mp4"
    smil_key = f"{prefix}/asset.smil"
    with open(mp4_path, "rb") as f:
        s3.put_object(Bucket=bucket, Key=mp4_key, Body=f.read())
    s3.put_object(Bucket=bucket, Key=smil_key, Body=smil_xml.encode("utf-8"))
    shutil.rmtree(tmpdir, ignore_errors=True)

    source_arn = f"arn:aws:s3:::{bucket}/{smil_key}"

    role_name = ctx.unique_name("sim2real-mpvod-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "mediapackage.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "source-access"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                # The four actions MediaPackage's own "Policy for Amazon S3 access for VOD
                # workflows" requires (mediapackage/latest/ug/setting-up-create-trust-rel.html),
                # granted on the bucket AND its objects exactly as that doc's policy does.
                # GetObject+ListBucket alone is NOT enough: CreateAsset validates the role
                # synchronously and rejected it with "source_arn bucket must be fetchable by
                # MediaPackage. Please ensure the source role and bucket access policy allow the
                # s3:GetBucketLocation action", then the same error naming
                # s3:GetBucketRequestPayment once GetBucketLocation was added.
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                            "s3:GetBucketLocation",
                            "s3:GetBucketRequestPayment",
                            "s3:ListBucket",
                        ],
                        "Resource": [
                            f"arn:aws:s3:::{bucket}/*",
                            f"arn:aws:s3:::{bucket}",
                        ],
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return {"bucket": bucket, "source_arn": source_arn, "role_arn": role_arn}


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _poll_until_playable(ctx, asset_id: str, config_id: str, timeout_s: float = 600.0, interval_s: float = 15.0):
    mpv = ctx.client("mediapackage-vod")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        described = mpv.describe_asset(Id=asset_id)
        endpoint = next(
            (e for e in described["EgressEndpoints"] if e["PackagingConfigurationId"] == config_id),
            None,
        )
        if endpoint is not None:
            last_status = endpoint.get("Status")
            if last_status == "PLAYABLE":
                return endpoint
            assert last_status != "FAILED", f"asset {asset_id} egress endpoint reported FAILED"
        time.sleep(interval_s)
    raise AssertionError(
        f"asset {asset_id} egress endpoint never reached PLAYABLE within {timeout_s}s "
        f"(last observed status: {last_status!r})"
    )


def _http_get(ctx, url: str, timeout_s: float = 20.0) -> tuple[str, int]:
    try:
        target_url, route_headers = ctx.endpoint_route(url)
        with urllib.request.urlopen(urllib.request.Request(target_url, headers=route_headers), timeout=timeout_s) as resp:
            return resp.read().decode("utf-8", errors="replace"), resp.status
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", errors="replace"), e.code


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
