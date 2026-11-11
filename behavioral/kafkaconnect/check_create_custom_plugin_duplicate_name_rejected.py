"""create-custom-plugin-duplicate-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-custom-plugin-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["kafkaconnect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a second custom plugin with a name already in use is rejected with
    ConflictException; once the conflicting plugin is gone, the identical name is free again."""
    s3 = ctx.client("s3")
    kc = ctx.client("kafkaconnect")

    bucket = ctx.unique_name("sim2real-kc-dupname-").lower()
    if ctx.region == "us-east-1":  # us-east-1 rejects an explicit LocationConstraint on CreateBucket
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    key = "plugin.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_minimal_plugin_zip_bytes())
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    name = ctx.unique_name("sim2real-kc-dupname-plugin-")
    location = {"s3Location": {"bucketArn": f"arn:aws:s3:::{bucket}", "fileKey": key}}

    # Positive control: the first create with this name succeeds.
    first = kc.create_custom_plugin(name=name, contentType="ZIP", location=location)
    first_arn = first["customPluginArn"]
    ctx.on_cleanup(lambda: _best_effort_delete_plugin(kc, first_arn))
    assert first["customPluginState"] == "CREATING", first["customPluginState"]

    # Break exactly one thing: reuse the same name for a second create while the first still exists.
    code, message = _client_error(
        lambda: kc.create_custom_plugin(name=name, contentType="ZIP", location=location)
    )
    assert code == "ConflictException", code
    assert message == "Invalid parameter name: A resource with this name already exists.", message

    # Effect absent: the original plugin is unchanged, and no second plugin was created under this name.
    described = kc.describe_custom_plugin(customPluginArn=first_arn)
    assert described["name"] == name, described["name"]
    listed = kc.list_custom_plugins(namePrefix=name)["customPlugins"]
    assert len(listed) == 1, listed

    # DeleteCustomPlugin refuses a plugin still in CREATING; wait for it to settle before restoring.
    first_state = _poll_until(
        lambda: kc.describe_custom_plugin(customPluginArn=first_arn)["customPluginState"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=180,
        interval_s=3,
    )
    assert first_state == "ACTIVE", first_state

    # Restore: delete the conflicting plugin and confirm it is actually gone.
    kc.delete_custom_plugin(customPluginArn=first_arn)
    gone_code, gone_message = _wait_for_error(
        lambda: kc.describe_custom_plugin(customPluginArn=first_arn), timeout_s=120, interval_s=3
    )
    assert gone_code == "NotFoundException", gone_code
    assert gone_message == "Invalid parameter customPluginArn: The requested resource doesn\u2019t exist.", gone_message

    # Identical call now succeeds: the name is free once the conflicting plugin is gone. Terminal
    # read is independent of the mutating call: a fresh DescribeCustomPlugin at the destination.
    second_arn = kc.create_custom_plugin(name=name, contentType="ZIP", location=location)["customPluginArn"]
    ctx.on_cleanup(lambda: _best_effort_delete_plugin(kc, second_arn))
    final_state = _poll_until(
        lambda: kc.describe_custom_plugin(customPluginArn=second_arn)["customPluginState"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=180,
        interval_s=3,
    )
    assert final_state == "ACTIVE", final_state


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


def _best_effort_delete_plugin(kc, plugin_arn: str) -> None:
    try:
        kc.delete_custom_plugin(customPluginArn=plugin_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


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
