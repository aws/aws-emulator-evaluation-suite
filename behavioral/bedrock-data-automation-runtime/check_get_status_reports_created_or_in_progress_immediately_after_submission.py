"""get-status-reports-created-or-in-progress-immediately-after-submission."""
from __future__ import annotations

import base64
import time

from behavioral_harness import tags

CHECK = "get-status-reports-created-or-in-progress-immediately-after-submission"
GROUP = "state"
SERVICES = ["bedrock-data-automation-runtime"]

# Region-pinned: each value names the documented BDA cross-region-inference source region's
# profile suffix, not a default-region assumption -- there is no region-agnostic profile ARN.
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

_MINIMAL_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
    "+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Every GetDataAutomationStatus read before the job ends reports Created or InProgress with
    jobSubmissionTime and no jobCompletionTime, and for a one-pixel PNG the job ends in ClientError
    / InvalidImage ('Image format is invalid or not supported.') with jobCompletionTime set.
    """
    bda = ctx.client("bedrock-data-automation-runtime")
    s3 = ctx.client("s3")
    profile_arn = _profile_arn(ctx)
    project_arn = _create_project(ctx)
    _, input_uri, output_uri = _create_input_bucket_and_object(ctx, s3)

    # The one-pixel PNG is rejected within seconds, so a first read can already find the job ended
    # in its expected outcome, ClientError / InvalidImage; only that read missed the window, and a
    # fresh submission is made, up to _ATTEMPTS, until a first read finds the job still open. Any
    # other first status (Success, ServiceError, another ClientError) fails at once.
    for _attempt in range(_ATTEMPTS):
        invocation_arn = bda.invoke_data_automation_async(
            inputConfiguration={"s3Uri": input_uri},
            outputConfiguration={"s3Uri": output_uri},
            dataAutomationProfileArn=profile_arn,
            dataAutomationConfiguration={"dataAutomationProjectArn": project_arn},
        )["invocationArn"]

        first = bda.get_data_automation_status(invocationArn=invocation_arn)
        if not (first["status"] == "ClientError" and first.get("errorType") == "InvalidImage"):
            break
    assert first["status"] in _NON_TERMINAL, (
        f"expected a non-terminal status right after submission, got {first['status']!r} "
        "(job completed implausibly fast, or status wasn't tracked at all)"
    )
    assert "jobSubmissionTime" in first, (
        f"expected jobSubmissionTime to be set on the status response, got keys "
        f"{sorted(first.keys())!r}"
    )
    assert first.get("jobCompletionTime") is None, (
        f"expected no jobCompletionTime immediately after submission, got "
        f"{first.get('jobCompletionTime')!r}"
    )

    status_resp = _poll_until_terminal(bda, invocation_arn)

    assert status_resp["status"] == "ClientError", (
        f"expected the one-pixel PNG job to end in ClientError, got {status_resp['status']!r}"
    )
    assert status_resp.get("errorType") == "InvalidImage", (
        f"expected errorType InvalidImage, got {status_resp.get('errorType')!r}"
    )
    expected_message = "Image format is invalid or not supported."
    assert status_resp.get("errorMessage") == expected_message, (
        f"expected errorMessage {expected_message!r}, got {status_resp.get('errorMessage')!r}"
    )
    assert "jobSubmissionTime" in status_resp, (
        f"expected jobSubmissionTime on the terminal status, got keys {sorted(status_resp.keys())!r}"
    )
    assert status_resp.get("jobCompletionTime") is not None, (
        f"expected jobCompletionTime on the terminal status, got keys {sorted(status_resp.keys())!r}"
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


_NON_TERMINAL = {"Created", "InProgress"}
_ATTEMPTS = 5


def _poll_until_terminal(bda, invocation_arn, timeout_s=300.0, interval_s=3.0):
    """Read GetDataAutomationStatus until the status leaves Created/InProgress. Every
    non-terminal read must carry jobSubmissionTime and no jobCompletionTime. Raises on
    timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        resp = bda.get_data_automation_status(invocationArn=invocation_arn)
        if resp["status"] not in _NON_TERMINAL:
            return resp
        assert "jobSubmissionTime" in resp, (
            f"expected jobSubmissionTime on a {resp['status']} read, got keys {sorted(resp.keys())!r}"
        )
        assert resp.get("jobCompletionTime") is None, (
            f"expected no jobCompletionTime while {resp['status']}, got {resp.get('jobCompletionTime')!r}"
        )
        if time.monotonic() >= deadline:
            raise AssertionError(f"job {invocation_arn} still {resp['status']} after {timeout_s}s")
        time.sleep(interval_s)


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
    return base64.b64decode(_MINIMAL_PNG_B64)


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
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    key = "input/asset.png"
    s3.put_object(Bucket=bucket, Key=key, Body=_minimal_png_bytes(), ContentType="image/png")
    return bucket, f"s3://{bucket}/{key}", f"s3://{bucket}/output/"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
