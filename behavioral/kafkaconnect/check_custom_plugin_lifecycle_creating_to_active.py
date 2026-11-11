"""custom-plugin-lifecycle-creating-to-active."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "custom-plugin-lifecycle-creating-to-active"
GROUP = "state"
SERVICES = ["kafkaconnect"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCustomPlugin starts CREATING and transitions to ACTIVE with revision 1."""
    s3 = ctx.client("s3")
    kc = ctx.client("kafkaconnect")

    bucket = ctx.unique_name("sim2real-kc-plugin-bucket-").lower()
    # us-east-1 is the one region S3's CreateBucket rejects an explicit LocationConstraint for.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    key = "plugin.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_minimal_plugin_zip_bytes())
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    name = ctx.unique_name("sim2real-kc-plugin-")
    created = kc.create_custom_plugin(
        name=name,
        contentType="ZIP",
        location={"s3Location": {"bucketArn": f"arn:aws:s3:::{bucket}", "fileKey": key}},
        tags={"sim2real": CHECK},
    )
    plugin_arn = created["customPluginArn"]
    ctx.on_cleanup(lambda: kc.delete_custom_plugin(customPluginArn=plugin_arn))

    assert created["customPluginState"] == "CREATING", created["customPluginState"]
    assert created["revision"] == 1, created["revision"]

    final_state = _poll_until(
        lambda: kc.describe_custom_plugin(customPluginArn=plugin_arn)["customPluginState"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=180,
        interval_s=3,
    )
    assert final_state == "ACTIVE", final_state

    described = kc.describe_custom_plugin(customPluginArn=plugin_arn)
    assert described["latestRevision"]["revision"] == 1, described["latestRevision"]


def _minimal_plugin_zip_bytes() -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
    return buf.getvalue()


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
