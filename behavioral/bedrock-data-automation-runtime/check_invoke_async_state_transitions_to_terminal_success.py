"""invoke-async-state-transitions-to-terminal-success."""
from __future__ import annotations

import struct
import time
import zlib

from behavioral_harness import tags

CHECK = "invoke-async-state-transitions-to-terminal-success"
GROUP = "state"
SERVICES = ["bedrock-data-automation-runtime"]

# Cross-region-inference profile suffixes are per-source-region by AWS's own documented mapping,
# not an arbitrary resource-region pin.
_PROFILE_SUFFIX_BY_REGION = {
    "us-east-1": "us.data-automation-v1",
    "us-west-2": "us.data-automation-v1",
    "us-east-2": "us.data-automation-v1",
    "ca-central-1": "na.data-automation-v1",
    "eu-central-1": "eu.data-automation-v1",
    "eu-west-1": "eu.data-automation-v1",
    "eu-west-2": "eu.data-automation-v1",
    "eu-south-2": "eu.data-automation-v1",
    "ap-south-1": "apac.data-automation-v1",
    "ap-southeast-2": "apac.data-automation-v1",
    "ap-northeast-1": "apac.data-automation-v1",
    "us-gov-west-1": "us-gov.data-automation-v1",
}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An InvokeDataAutomationAsync job reaches Success in GetDataAutomationStatus with
    jobCompletionTime >= jobSubmissionTime, a non-negative jobDurationInSeconds and an output s3Uri
    under the requested location.
    """
    bda = ctx.client("bedrock-data-automation-runtime")
    s3 = ctx.client("s3")
    profile_arn = _profile_arn(ctx)
    project_arn = _create_project(ctx)
    _, input_uri, output_uri = _create_input_bucket_and_object(ctx, s3)

    invocation_arn = bda.invoke_data_automation_async(
        inputConfiguration={"s3Uri": input_uri},
        outputConfiguration={"s3Uri": output_uri},
        dataAutomationProfileArn=profile_arn,
        dataAutomationConfiguration={"dataAutomationProjectArn": project_arn},
    )["invocationArn"]

    def probe():
        return bda.get_data_automation_status(invocationArn=invocation_arn)

    final = _poll_until(
        probe,
        lambda r: r["status"] in {"Success", "ServiceError", "ClientError"},
        timeout_s=250.0,
        interval_s=8.0,
    )

    assert final["status"] == "Success", f"job reached terminal state {final['status']!r}, not Success"
    assert "jobSubmissionTime" in final, f"terminal Success response missing jobSubmissionTime: {final!r}"
    assert "jobCompletionTime" in final, f"terminal Success response missing jobCompletionTime: {final!r}"
    assert final["jobCompletionTime"] >= final["jobSubmissionTime"], (
        f"jobCompletionTime {final['jobCompletionTime']!r} precedes "
        f"jobSubmissionTime {final['jobSubmissionTime']!r}"
    )
    assert final["jobDurationInSeconds"] >= 0, (
        f"expected a non-negative jobDurationInSeconds, got {final['jobDurationInSeconds']!r}"
    )
    assert final["outputConfiguration"]["s3Uri"].startswith(output_uri), (
        f"expected output s3Uri under {output_uri!r}, got {final['outputConfiguration']['s3Uri']!r}"
    )


def _create_project(ctx):
    ctrl = ctx.client("bedrock-data-automation")
    project_name = ctx.unique_name("sim2real-bda-proj-").replace("_", "-")[:128]
    resp = ctrl.create_data_automation_project(
        projectName=project_name,
        projectStage="LIVE",
        standardOutputConfiguration={},
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    project_arn = resp["projectArn"]
    ctx.on_cleanup(lambda: ctrl.delete_data_automation_project(projectArn=project_arn))
    return project_arn


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _profile_arn(ctx):
    suffix = _PROFILE_SUFFIX_BY_REGION.get(ctx.region)
    if suffix is None:
        raise AssertionError(
            f"region {ctx.region} is not one of the documented BDA cross-region-inference "
            "source regions; cannot construct a data-automation-profile ARN"
        )
    return f"arn:aws:bedrock:{ctx.region}:{_account_id(ctx)}:data-automation-profile/{suffix}"


def _minimal_png_bytes():
    return _generate_png_bytes()


def _generate_png_bytes(width=64, height=64, rgb=(30, 120, 200)):
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(
            ">I", zlib.crc32(tag + data) & 0xFFFFFFFF
        )

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    row = bytes(rgb) * width
    raw = (b"\x00" + row) * height
    idat = zlib.compress(raw)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def _empty_and_delete_bucket(s3, bucket):
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _create_input_bucket_and_object(ctx, s3):
    bucket = ctx.unique_name("sim2real-bda-").replace("_", "-").lower()
    if ctx.region != "us-east-1":
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    else:
        s3.create_bucket(Bucket=bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    key = "input/asset.png"
    s3.put_object(Bucket=bucket, Key=key, Body=_minimal_png_bytes(), ContentType="image/png")
    return bucket, f"s3://{bucket}/{key}", f"s3://{bucket}/output/"


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
