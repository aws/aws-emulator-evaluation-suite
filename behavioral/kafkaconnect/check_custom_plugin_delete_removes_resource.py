"""custom-plugin-delete-removes-resource."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-plugin-delete-removes-resource"
GROUP = "state"
SERVICES = ["kafkaconnect"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCustomPlugin removes the plugin; DescribeCustomPlugin then raises NotFoundException."""
    s3 = ctx.client("s3")
    kc = ctx.client("kafkaconnect")

    bucket = ctx.unique_name("sim2real-kc-plugin-bucket-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    key = "plugin.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_minimal_plugin_zip_bytes())
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    plugin_arn = kc.create_custom_plugin(
        name=ctx.unique_name("sim2real-kc-plugin-"),
        contentType="ZIP",
        location={"s3Location": {"bucketArn": f"arn:aws:s3:::{bucket}", "fileKey": key}},
        tags={"sim2real": "custom-plugin-delete-removes-resource"},
    )["customPluginArn"]

    # Positive control: the plugin must actually reach ACTIVE before its deletion means
    # anything — otherwise a target that always fails creation would still score green here.
    final_creation_state = _poll_until(
        lambda: kc.describe_custom_plugin(customPluginArn=plugin_arn)["customPluginState"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=180,
        interval_s=3,
    )
    assert final_creation_state == "ACTIVE", (
        f"expected the plugin to reach ACTIVE before delete, got {final_creation_state!r}"
    )

    kc.delete_custom_plugin(customPluginArn=plugin_arn)

    final_code, final_message = _wait_for_error(
        lambda: kc.describe_custom_plugin(customPluginArn=plugin_arn), timeout_s=120, interval_s=3
    )
    assert final_code == "NotFoundException", f"expected NotFoundException, got {final_code!r}"
    assert final_message == "Invalid parameter customPluginArn: The requested resource doesn\u2019t exist.", final_message

    # The dead id is also unusable for a mutation, not just a read: a second delete on the
    # same ARN must fail the same way rather than silently no-op.
    redelete_code, redelete_message = _client_error(
        lambda: kc.delete_custom_plugin(customPluginArn=plugin_arn)
    )
    assert redelete_code == "NotFoundException", f"expected NotFoundException, got {redelete_code!r}"
    assert redelete_message == "Invalid parameter customPluginArn: The requested resource doesn\u2019t exist.", redelete_message


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


def _wait_for_error(fn, *, timeout_s=60.0, interval_s=2.0):
    """Re-call fn() until it raises a ClientError and return its (code, message); raise if it
    still succeeds when the budget runs out."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"the call still succeeded after {timeout_s}s; last={last!r}")


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
