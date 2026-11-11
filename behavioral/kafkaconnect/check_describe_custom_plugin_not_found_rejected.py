"""describe-custom-plugin-not-found-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-custom-plugin-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["kafkaconnect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeCustomPlugin on a well-formed but never-created ARN is rejected with NotFoundException."""
    s3 = ctx.client("s3")
    kc = ctx.client("kafkaconnect")

    bucket = ctx.unique_name("sim2real-kc-notfound-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    key = "plugin.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_minimal_plugin_zip_bytes())
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    real_arn = kc.create_custom_plugin(
        name=ctx.unique_name("sim2real-kc-notfound-plugin-"),
        contentType="ZIP",
        location={"s3Location": {"bucketArn": f"arn:aws:s3:::{bucket}", "fileKey": key}},
    )["customPluginArn"]
    ctx.on_cleanup(lambda: _delete_plugin_when_settled(kc, real_arn))

    # Break exactly one thing: a syntactically valid ARN of a plugin that was never created.
    bogus_arn = real_arn.rsplit("/", 1)[0] + "/00000000-0000-0000-0000-000000000000"
    code, message = _client_error(lambda: kc.describe_custom_plugin(customPluginArn=bogus_arn))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid parameter customPluginArn: The requested resource doesn\u2019t exist.", message

    # Positive control: describing the real ARN in the same file still works.
    described = kc.describe_custom_plugin(customPluginArn=real_arn)
    assert described["customPluginArn"] == real_arn, (
        f"expected customPluginArn {real_arn!r}, got {described['customPluginArn']!r}"
    )


def _minimal_plugin_zip_bytes() -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
    return buf.getvalue()


def _client_error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so an
    emulator that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _delete_plugin_when_settled(kc, plugin_arn: str, timeout_s: float = 180.0) -> None:
    """Teardown: DeleteCustomPlugin refuses a plugin in CREATING, so wait for it to settle
    first; a plugin that is already gone is fine."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            state = kc.describe_custom_plugin(customPluginArn=plugin_arn)["customPluginState"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if state != "CREATING" or time.monotonic() >= deadline:
            break
        time.sleep(3)
    try:
        kc.delete_custom_plugin(customPluginArn=plugin_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
