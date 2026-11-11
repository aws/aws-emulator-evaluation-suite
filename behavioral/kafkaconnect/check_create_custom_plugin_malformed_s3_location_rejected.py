"""create-custom-plugin-malformed-s3-location-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-custom-plugin-malformed-s3-location-rejected"
GROUP = "overly-permissive"
SERVICES = ["kafkaconnect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A bucketArn that is not a valid S3 ARN is rejected with BadRequestException, not accepted."""
    s3 = ctx.client("s3")
    kc = ctx.client("kafkaconnect")

    bucket = ctx.unique_name("sim2real-kc-malformed-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "create-custom-plugin-malformed-s3-location-rejected"}]},
    )
    key = "plugin.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_minimal_plugin_zip_bytes())
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    # Break exactly one thing: bucketArn is a plain bucket name, not "arn:aws:s3:::<bucket>".
    bad_location = {"s3Location": {"bucketArn": bucket, "fileKey": key}}
    bad_name = ctx.unique_name("sim2real-kc-malformed-plugin-")
    code, message = _client_error(
        lambda: kc.create_custom_plugin(
            name=bad_name,
            contentType="ZIP",
            location=bad_location,
        )
    )
    assert code == "BadRequestException", code
    assert message == "Invalid parameter bucketArn: Invalid ARN.", message

    # Effect absent: no plugin with that intended name exists.
    listed = kc.list_custom_plugins(namePrefix=bad_name)["customPlugins"]
    assert listed == [], listed

    # Positive control: the identical location with a correctly-formed bucketArn succeeds.
    good_name = ctx.unique_name("sim2real-kc-malformed-plugin-ok-")
    good = kc.create_custom_plugin(
        name=good_name,
        contentType="ZIP",
        location={"s3Location": {"bucketArn": f"arn:aws:s3:::{bucket}", "fileKey": key}},
        tags={"sim2real": "create-custom-plugin-malformed-s3-location-rejected"},
    )
    good_arn = good["customPluginArn"]
    ctx.on_cleanup(lambda: _delete_plugin_when_settled(kc, good_arn))
    assert good["customPluginState"] == "CREATING", good["customPluginState"]

    # Terminal assertion is an independent read at the destination, not the create call's own
    # response: the well-formed plugin is now visible through ListCustomPlugins.
    good_listed = kc.list_custom_plugins(namePrefix=good_name)["customPlugins"]
    assert [p["customPluginArn"] for p in good_listed] == [good_arn], good_listed


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
