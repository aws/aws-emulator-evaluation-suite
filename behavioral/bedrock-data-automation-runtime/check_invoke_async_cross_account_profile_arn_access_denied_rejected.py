"""invoke-async-cross-account-profile-arn-access-denied-rejected."""
from __future__ import annotations

import base64
import time

from behavioral_harness import tags

CHECK = "invoke-async-cross-account-profile-arn-access-denied-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-data-automation-runtime"]

# Region-pinned: each region maps to the BDA cross-region-inference profile suffix AWS
# documents for it (there is no API to look this up, so the mapping itself is the fixture).
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

_FOREIGN_ACCOUNT = "111122223333"


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeDataAutomationAsync rejects a dataAutomationProfileArn scoped to an
    inaccessible foreign account with AccessDeniedException and creates no invocation,
    while the caller's own profile ARN still succeeds (positive control)."""
    bda = ctx.client("bedrock-data-automation-runtime")
    s3 = ctx.client("s3")
    own_profile_arn = _profile_arn(ctx)
    suffix = own_profile_arn.rsplit("/", 1)[1]
    foreign_profile_arn = f"arn:aws:bedrock:{ctx.region}:{_FOREIGN_ACCOUNT}:data-automation-profile/{suffix}"
    account = _account_id(ctx)
    assert account != _FOREIGN_ACCOUNT, "test account collides with the fixed foreign account id"

    project_arn = _create_project(ctx)
    _, input_uri, output_uri = _create_input_bucket_and_object(ctx, s3)

    # Negative: a profile ARN in an account we have no permission on.
    code, message = _error(
        lambda: bda.invoke_data_automation_async(
            inputConfiguration={"s3Uri": input_uri},
            outputConfiguration={"s3Uri": output_uri},
            dataAutomationProfileArn=foreign_profile_arn,
            dataAutomationConfiguration={"dataAutomationProjectArn": project_arn},
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException for a foreign-account profile ARN, got {code!r}"
    assert message == f"User: {account} is not authorized to access this resource", message

    # Positive control: the caller's own profile ARN in the same region succeeds.
    invocation_arn = bda.invoke_data_automation_async(
        inputConfiguration={"s3Uri": input_uri},
        outputConfiguration={"s3Uri": output_uri},
        dataAutomationProfileArn=own_profile_arn,
        dataAutomationConfiguration={"dataAutomationProjectArn": project_arn},
    )["invocationArn"]
    assert invocation_arn.startswith("arn:aws:bedrock:"), f"expected a bedrock invocation ARN, got {invocation_arn!r}"

    # Independent read at the destination: the invocation is tracked server-side and runs to the
    # end the one-pixel input leads to, ClientError / InvalidImage.
    status_resp = _poll_until_terminal(ctx, bda, invocation_arn)
    assert status_resp["status"] == "ClientError", (
        f"expected the accepted one-pixel PNG invocation {invocation_arn!r} to end in ClientError, "
        f"got {status_resp['status']!r}"
    )
    assert status_resp.get("errorType") == "InvalidImage", (
        f"expected errorType InvalidImage, got {status_resp.get('errorType')!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until_terminal(ctx, bda, invocation_arn, timeout_s=120.0, interval_s=2.0):
    """Read GetDataAutomationStatus until the status leaves Created/InProgress; return that read."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        resp = bda.get_data_automation_status(invocationArn=invocation_arn)
        if resp["status"] not in ("Created", "InProgress"):
            return resp
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"job {invocation_arn}: the run budget ended first; not graded")
            raise AssertionError(f"job {invocation_arn} still {resp['status']} after {timeout_s}s")
        time.sleep(interval_s)


def _create_project(ctx):
    ctrl = ctx.client("bedrock-data-automation")
    project_name = ctx.unique_name("sim2real-bda-proj-").replace("_", "-")[:128]
    resp = ctrl.create_data_automation_project(
        projectName=project_name, projectStage="LIVE", standardOutputConfiguration={}
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
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    key = "input/asset.png"
    s3.put_object(Bucket=bucket, Key=key, Body=_minimal_png_bytes(), ContentType="image/png")
    return bucket, f"s3://{bucket}/{key}", f"s3://{bucket}/output/"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

