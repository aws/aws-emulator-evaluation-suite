"""platform-version-custom-tags-round-trip."""
from __future__ import annotations

import io
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "platform-version-custom-tags-round-trip"
GROUP = "representation"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:elasticbeanstalk-custom-platform-quota")
def run(ctx: Any) -> None:
    """Tags given to CreatePlatformVersion, including a value with leading/trailing whitespace and
    punctuation, round-trip unchanged through ListTagsForResource on the platform ARN."""
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")

    bucket = eb.create_storage_location()["S3Bucket"]
    key = ctx.unique_name("sim2real-eb-platform-") + "/platform.zip"
    body = _build_minimal_platform_bundle()
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    platform_name = ctx.unique_name("sim2real-eb-plat-")
    marker = ctx.unique_name("sim2real-tag-")
    # AWS allows only letters, digits, whitespace and . : _ / = + - @ in tag values (stricter than
    # the model), and the model forbids an empty value.
    special_value = "  tag.value:with_various/allowed=chars+here-now@2026  "
    tags = [
        {"Key": "sim2real-owner", "Value": marker},
        {"Key": "sim2real-special", "Value": special_value},
    ]

    resp = eb.create_platform_version(
        PlatformName=platform_name,
        PlatformVersion="1.0.0",
        PlatformDefinitionBundle={"S3Bucket": bucket, "S3Key": key},
        Tags=tags,
    )
    platform_arn = resp["PlatformSummary"]["PlatformArn"]
    ctx.on_cleanup(lambda: _delete_platform(ctx, platform_arn))

    tag_resp = eb.list_tags_for_resource(ResourceArn=platform_arn)
    got = {t["Key"]: t["Value"] for t in tag_resp["ResourceTags"]}
    assert got.get("sim2real-owner") == marker, f"tag value mismatch: {got}"
    assert "sim2real-special" in got, f"special-value tag key missing: {got}"
    assert got["sim2real-special"] == special_value, (
        f"tag value with whitespace/special chars not preserved byte-for-byte: "
        f"wrote {special_value!r}, read back {got['sim2real-special']!r}"
    )


def _build_minimal_platform_bundle() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "platform.yaml",
            "version: 1\n"
            "provisioner:\n"
            "  type: packer\n"
            "executables: {}\n",
        )
        zf.writestr(
            "builder.json",
            '{"builders": [{"type": "amazon-ebs"}]}\n',
        )
    return buf.getvalue()


def _delete_platform(ctx: Any, platform_arn: str, timeout_s: float = 840.0) -> None:
    """Delete the platform version once its build settles, within the cleanup budget; a version
    already gone (InvalidParameterValue "... not found") is the wanted state, anything else raises."""
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            desc = eb.describe_platform_version(PlatformArn=platform_arn).get("PlatformDescription", {})
            if desc.get("PlatformStatus") in ("Ready", "Failed", None):
                eb.delete_platform_version(PlatformArn=platform_arn)
                return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidParameterValue" and "found" in exc.response["Error"].get("Message", "").lower():
                return
            if code != "OperationInProgressFailure":
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"platform version {platform_arn} could not be deleted within {timeout_s:.0f}s")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
