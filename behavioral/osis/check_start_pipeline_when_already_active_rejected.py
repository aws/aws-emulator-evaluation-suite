"""start-pipeline-when-already-active-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-pipeline-when-already-active-rejected"
GROUP = "overly-permissive"
SERVICES = ["osis"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartPipeline on a pipeline that is already ACTIVE is rejected with
    ConflictException and the pipeline's status is left untouched, while the same
    StartPipeline call succeeds once the pipeline has actually been stopped."""
    osis = ctx.client("osis")
    name = ctx.unique_name("sim2real-osis-")
    fixture = _create_pipeline_role_and_bucket(ctx)
    config = _pipeline_config(fixture["bucket"], fixture["role_arn"], ctx.region)
    _create_pipeline_with_retry(ctx, osis, name, 1, 1, config)
    ctx.on_cleanup(lambda: _delete_pipeline_best_effort(ctx, name))
    status = _wait_for_pipeline_status(ctx, name, {"ACTIVE", "CREATE_FAILED"}, timeout_s=1200)
    assert status == "ACTIVE", f"positive control: pipeline entered {status!r} instead of ACTIVE"

    code, message = _error(lambda: osis.start_pipeline(PipelineName=name))
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    # message varies: AWS lists the eligible statuses (STOPPED, START_FAILED, CREATE_FAILED)
    # in a different order from call to call, so the list is compared as a set and the rest of
    # the message exactly.
    head = "Only pipelines with one of the following statuses are eligible for starting: "
    tail = ". The current status is ACTIVE."
    assert message.startswith(head) and message.endswith(tail), (
        f"expected {head!r}<statuses>{tail!r}, got {message!r}"
    )
    eligible = set(message[len(head):-len(tail)].split(", "))
    assert eligible == {"STOPPED", "START_FAILED", "CREATE_FAILED"}, (
        f"expected the eligible statuses STOPPED, START_FAILED, CREATE_FAILED, got {message!r}"
    )
    unaffected = osis.get_pipeline(PipelineName=name)["Pipeline"]["Status"]
    assert unaffected == "ACTIVE", "rejected StartPipeline must not change pipeline status"

    osis.stop_pipeline(PipelineName=name)
    stopped = _wait_for_pipeline_status(ctx, name, {"STOPPED", "START_FAILED"}, timeout_s=600)
    assert stopped == "STOPPED", f"restore leg: pipeline entered {stopped!r} instead of STOPPED"

    osis.start_pipeline(PipelineName=name)
    restarted = _wait_for_pipeline_status(ctx, name, {"ACTIVE", "START_FAILED"}, timeout_s=600)
    assert restarted == "ACTIVE", f"identical StartPipeline call entered {restarted!r} instead of ACTIVE"


# ===== helpers =====

def _error(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _pipeline_config(bucket: str, role_arn: str, region: str) -> str:
    return f"""version: "2"
osis-behav-pipeline:
  source:
    http:
      path: "/ingest"
  sink:
    - s3:
        bucket: "{bucket}"
        codec:
          ndjson:
        aws:
          sts_role_arn: "{role_arn}"
          region: "{region}"
        threshold:
          event_count: 1
          maximum_size: "1mb"
          event_collect_timeout: "60s"
"""


def _create_pipeline_role_and_bucket(ctx) -> dict[str, str]:
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region
    bucket_name = ctx.unique_name("sim2real-osis-behav-")
    if region == "us-east-1":
        # us-east-1 is CreateBucket's own region-pinned special case: it rejects an
        # explicit LocationConstraint for its own region.
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]},
    )

    role_name = ctx.unique_name("sim2real-osis-behav-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "osis-pipelines.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _detach_and_delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="osis-behav-s3-sink",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:PutObject",
                            "s3:PutObjectAcl",
                            "s3:AbortMultipartUpload",
                            "s3:ListBucket",
                        ],
                        "Resource": [
                            f"arn:aws:s3:::{bucket_name}",
                            f"arn:aws:s3:::{bucket_name}/*",
                        ],
                    }
                ],
            }
        ),
    )
    return {"role_arn": role_arn, "bucket": bucket_name, "role_name": role_name}


def _detach_and_delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _empty_and_delete_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_pipeline_with_retry(
    ctx, osis, name: str, min_units: int, max_units: int, config: str, timeout_s: float = 90
) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            osis.create_pipeline(
                PipelineName=name,
                MinUnits=min_units,
                MaxUnits=max_units,
                PipelineConfigurationBody=config,
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_for_pipeline_status(
    ctx, name: str, target_statuses: set[str], timeout_s: float = 1200, *, bounded: bool = True
) -> str:
    """Poll GetPipeline every 2 s; a bounded wait also ends 5 s before the runner's budget does."""
    osis = ctx.client("osis")
    if bounded:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = ""
    while time.monotonic() < deadline:
        last = osis.get_pipeline(PipelineName=name)["Pipeline"]["Status"]
        if last in target_statuses:
            return last
        time.sleep(2)
    if bounded and _budget_spent(ctx):
        raise TimeoutError(f"pipeline {name} reaching {target_statuses}: the run budget ended first; not graded")
    raise AssertionError(f"pipeline {name} did not reach {target_statuses} within {timeout_s:.0f}s (last={last})")


def _delete_pipeline_best_effort(ctx, name: str) -> None:
    osis = ctx.client("osis")
    try:
        _wait_for_pipeline_status(
            ctx,
            name,
            {"ACTIVE", "STOPPED", "CREATE_FAILED", "UPDATE_FAILED", "START_FAILED"},
            timeout_s=720,
            bounded=False,
        )
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    # DeletePipeline answers ConflictException while a transition settles: retry it, raise the rest.
    deadline = time.monotonic() + 150
    while True:
        try:
            osis.delete_pipeline(PipelineName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code == "ConflictException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
