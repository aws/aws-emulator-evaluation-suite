"""custom-platform-version-tags-round-trip."""
from __future__ import annotations

import io
import time
import zipfile

from behavioral_harness import tags

CHECK = "custom-platform-version-tags-round-trip"
GROUP = "representation"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:elasticbeanstalk-custom-platform-quota")
def run(ctx) -> None:
    """Tags supplied at CreatePlatformVersion read back byte-identical via ListTagsForResource,
    including unicode and max-length values, and DescribePlatformVersion reports the same
    PlatformArn/PlatformName/PlatformVersion."""
    # CreatePlatformVersion starts a real CodeBuild-based platform build; even a minimal bundle
    # takes minutes to reach a terminal PlatformStatus.
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")

    bucket = eb.create_storage_location()["S3Bucket"]
    platform_name = ctx.unique_name("sim2real-eb-plat-")
    platform_version = "1.0.0"
    key = f"{platform_name}/platform-definition.zip"

    bundle = _build_minimal_platform_bundle()
    s3.put_object(Bucket=bucket, Key=key, Body=bundle)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    # AWS rejects a non-BMP code point (e.g. an emoji outside U+0000-U+FFFF) in a tag
    # value with InvalidParameterValue "Invalid unicode xml character". The BMP CJK/Latin-1
    # mix below is the widest unicode value CreatePlatformVersion actually accepts.
    unicode_value = "\u65e5\u672c\u8a9e-caf\u00e9-\u00fc\u00f1\u00ee"
    boundary_value = "x" * 256  # Tag.Value max length per the EB API model

    tags = [
        {"Key": "sim2real:unicode", "Value": unicode_value},
        {"Key": "sim2real:boundary", "Value": boundary_value},
        {"Key": "Sim2Real-Mixed_Case.Key", "Value": "plain-ascii-value"},
    ]

    create_resp = eb.create_platform_version(
        PlatformName=platform_name,
        PlatformVersion=platform_version,
        PlatformDefinitionBundle={"S3Bucket": bucket, "S3Key": key},
        Tags=tags,
    )
    platform_arn = create_resp["PlatformSummary"]["PlatformArn"]
    ctx.on_cleanup(lambda: _delete_platform(eb, platform_arn))

    tags_resp = eb.list_tags_for_resource(ResourceArn=platform_arn)
    returned = {t["Key"]: t["Value"] for t in tags_resp["ResourceTags"]}
    expected = {t["Key"]: t["Value"] for t in tags}

    for key_, value in expected.items():
        assert key_ in returned, f"tag key {key_!r} missing from ListTagsForResource"
        assert returned[key_] == value, (
            f"tag {key_!r} value mismatch: wrote {value!r}, read back {returned[key_]!r}"
        )

    described = eb.describe_platform_version(PlatformArn=platform_arn)["PlatformDescription"]
    assert described["PlatformArn"] == platform_arn, (
        f"DescribePlatformVersion PlatformArn mismatch: expected {platform_arn!r}, "
        f"got {described['PlatformArn']!r}"
    )
    assert described["PlatformName"] == platform_name, (
        f"DescribePlatformVersion PlatformName mismatch: expected {platform_name!r}, "
        f"got {described['PlatformName']!r}"
    )
    assert described["PlatformVersion"] == platform_version, (
        f"DescribePlatformVersion PlatformVersion mismatch: expected {platform_version!r}, "
        f"got {described['PlatformVersion']!r}"
    )


def _build_minimal_platform_bundle() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "platform.yaml",
            'version: "1.0"\n'
            "provisioner:\n"
            "  type: packer\n",
        )
        zf.writestr("Dockerfile", "FROM scratch\n")
    return buf.getvalue()


def _delete_platform(eb, platform_arn: str, timeout_s: float = 840.0) -> None:
    """Delete a custom platform once its build is terminal, retrying OperationInProgressFailure
    every 2 s; a Deleting/Deleted or not-found platform is already gone, anything else raises."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = eb.describe_platform_version(PlatformArn=platform_arn)["PlatformDescription"]["PlatformStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "InvalidParameterValue" and "found" in err.get("Message", "").lower():
                return
            raise
        if status in ("Deleting", "Deleted"):
            return
        if status in ("Ready", "Failed"):
            try:
                eb.delete_platform_version(PlatformArn=platform_arn)
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "OperationInProgressFailure":
                    raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"platform {platform_arn} still {status!r} after {timeout_s}s, not deleted")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
