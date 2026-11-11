"""cfn-glue-job-in-place-update-runs-retained-replacement-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-glue-job-in-place-update-runs-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "glue", "logs", "s3"]

#: A stack operation takes seconds to a few minutes; the bound only stops a hung poll.
_STACK_S = 600.0
#: A Python shell run starts and finishes within a few minutes; the job's own Timeout is 5 min.
_RUN_S = 420.0
#: A change or delete reaches every read within seconds; the bound only stops a hung poll.
_PROPAGATE_S = 60.0
#: One deadline for the whole teardown, within the suites' 1800 s cleanup budget.
_TEARDOWN_CAP_S = 1500.0
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_IAM = ["CAPABILITY_IAM"]
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)
_SCRIPT_KEY = "scripts/job.py"
_OUT_KEY = "out/greeting.txt"
#: The job writes its --greeting argument to --out_key in --out_bucket.
_SCRIPT = b"""import sys

import boto3
from awsglue.utils import getResolvedOptions

args = getResolvedOptions(sys.argv, ["out_bucket", "out_key", "greeting"])
boto3.client("s3").put_object(
    Bucket=args["out_bucket"], Key=args["out_key"], Body=args["greeting"].encode()
)
"""
#: GetJobRun's refusal of a run whose job does not exist.
_NO_RUN = ("EntityNotFoundException", "Job run not found for the given job name and runId.")
#: DeleteLogStream's refusal of a log stream that does not exist.
_NO_STREAM = ("ResourceNotFoundException", "The specified log stream does not exist.")
#: S3's refusal of a bucket that does not exist.
_NO_BUCKET = ("NoSuchBucket", "The specified bucket does not exist")
_TERMINAL = ("SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR", "EXPIRED")


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """An AWS::Glue::Job survives create, in-place update, retained replacement and delete.

    GetJob reads back Command, DefaultArguments and MaxCapacity; a run of the updated job writes
    its new default argument to S3, and a Name change under Retain keeps the old job.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-glue-job.html
    """
    cfn = ctx.client("cloudformation")
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    logs = ctx.client("logs")

    bucket = ctx.unique_name("sim2real-cfnreal-gj-").lower().replace("_", "-")
    stack_name = ctx.unique_name("sim2real-cfnreal-gj-")
    job_v1 = ctx.unique_name("sim2real-cfnreal-gj-a-")
    job_v2 = ctx.unique_name("sim2real-cfnreal-gj-b-")
    runs: list[str] = []

    # LIFO: an unfinished run stops, the stack goes, then the retained job, the run log streams
    # and the bucket. Teardown waits share one deadline of their own.
    limit: dict = {}
    ctx.on_cleanup(lambda: _drop_bucket(s3, bucket))
    ctx.on_cleanup(lambda: _delete_run_log_streams(logs, runs))
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_v1))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name, limit))
    ctx.on_cleanup(lambda: _stop_runs(glue, job_v1, runs, limit))
    # us-east-1 is the one region whose CreateBucket takes no LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})
    s3.put_object(Bucket=bucket, Key=_SCRIPT_KEY, Body=_SCRIPT)

    # ---- 1. create: CloudFormation view, Glue view ---------------------------------------------
    stack_id = cfn.create_stack(
        StackName=stack_name,
        Capabilities=_IAM,
        Tags=_TAGS,
        TemplateBody=_template(job_v1, bucket, "one", 0.0625),
    )["StackId"]
    created = _settle(ctx, cfn, stack_id)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"create ended {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    _assert_tracks(cfn, stack_id, "Job", job_v1)
    role_arn = _outputs(cfn, stack_id)["RoleArn"]
    _assert_job(_job(glue, job_v1), job_v1, role_arn, bucket, "one", 0.0625)

    # ---- 2. in place: the greeting argument, MaxCapacity and Description -----------------------
    body = _template(job_v1, bucket, "two", 1.0)
    _assert_updated_in_place(_update(ctx, cfn, stack_id, "Job", body, Capabilities=_IAM), job_v1)
    _assert_tracks(cfn, stack_id, "Job", job_v1)
    job = _poll(
        ctx,
        lambda: _job(glue, job_v1),
        lambda j: j.get("MaxCapacity") == 1.0,
        cap_s=_PROPAGATE_S,
        what=f"GetJob on {job_v1} to read the updated MaxCapacity",
    )
    _assert_job(job, job_v1, role_arn, bucket, "two", 1.0)

    # Behaviour: a run of the updated job executes the script with the new default argument.
    run_id = glue.start_job_run(JobName=job_v1)["JobRunId"]
    runs.append(run_id)
    job_run = _poll(
        ctx,
        lambda: glue.get_job_run(JobName=job_v1, RunId=run_id)["JobRun"],
        lambda r: r["JobRunState"] in _TERMINAL,
        cap_s=_RUN_S,
        interval_s=5.0,
        what=f"run {run_id} of {job_v1} to finish",
    )
    assert job_run["JobRunState"] == "SUCCEEDED", (
        f"the run must succeed, got {job_run['JobRunState']!r}: {job_run.get('ErrorMessage')!r}"
    )
    written = s3.get_object(Bucket=bucket, Key=_OUT_KEY)["Body"].read()
    assert written == b"two", f"the run must write the updated --greeting, got {written!r}"

    # ---- 3. Name forces replacement; UpdateReplacePolicy Retain keeps the old job --------------
    body = _template(job_v2, bucket, "two", 1.0)
    rows = _update(ctx, cfn, stack_id, "Job", body, Capabilities=_IAM)
    _assert_replaced_and_retained(rows, job_v1, job_v2)
    _assert_tracks(cfn, stack_id, "Job", job_v2)
    _assert_job(_job(glue, job_v2), job_v2, role_arn, bucket, "two", 1.0)
    _assert_job(_job(glue, job_v1), job_v1, role_arn, bucket, "two", 1.0)

    # ---- 4. DeleteStack: the job it owns is gone, the retained one stays -----------------------
    _delete_and_confirm(ctx, cfn, stack_id)
    want = ("EntityNotFoundException", "Job not found.")
    _await_error(ctx, lambda: glue.get_job(JobName=job_v2), want, "GetJob after DeleteStack")
    assert _job(glue, job_v1)["Name"] == job_v1, "the retained job survives DeleteStack"


def _description(greeting: str) -> str:
    return f"reality check job, greeting {greeting}"


def _command(bucket: str) -> dict:
    return {
        "Name": "pythonshell",
        "ScriptLocation": f"s3://{bucket}/{_SCRIPT_KEY}",
        "PythonVersion": "3.9",
    }


def _arguments(bucket: str, greeting: str) -> dict:
    return {"--out_bucket": bucket, "--out_key": _OUT_KEY, "--greeting": greeting}


def _template(name: str, bucket: str, greeting: str, capacity: float) -> str:
    objects_arn = f"arn:${{AWS::Partition}}:s3:::{bucket}/*"
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "JobRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "glue.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "ManagedPolicyArns": [
                            {
                                "Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/"
                                "service-role/AWSGlueServiceRole"
                            }
                        ],
                        "Policies": [
                            {
                                "PolicyName": "bucket",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": ["s3:GetObject", "s3:PutObject"],
                                            "Resource": {"Fn::Sub": objects_arn},
                                        }
                                    ],
                                },
                            }
                        ],
                    },
                },
                "Job": {
                    "Type": "AWS::Glue::Job",
                    # Name is create-only, so a new name replaces the job.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "Name": name,
                        "Description": _description(greeting),
                        "Role": {"Fn::GetAtt": ["JobRole", "Arn"]},
                        "GlueVersion": "3.0",
                        "Command": _command(bucket),
                        "DefaultArguments": _arguments(bucket, greeting),
                        "MaxCapacity": capacity,
                        "MaxRetries": 0,
                        "Timeout": 5,
                        "ExecutionProperty": {"MaxConcurrentRuns": 1},
                    },
                },
            },
            "Outputs": {"RoleArn": {"Value": {"Fn::GetAtt": ["JobRole", "Arn"]}}},
        }
    )


def _job(glue, name: str) -> dict:
    return glue.get_job(JobName=name)["Job"]


def _assert_job(
    job: dict, name: str, role_arn: str, bucket: str, greeting: str, capacity: float
) -> None:
    """Glue's view: GetJob carries exactly the template's settings."""
    got = {
        k: job.get(k)
        for k in (
            "Name",
            "Description",
            "Role",
            "GlueVersion",
            "Command",
            "DefaultArguments",
            "MaxCapacity",
            "MaxRetries",
            "Timeout",
            "ExecutionProperty",
        )
    }
    want = {
        "Name": name,
        "Description": _description(greeting),
        "Role": role_arn,
        "GlueVersion": "3.0",
        "Command": _command(bucket),
        "DefaultArguments": _arguments(bucket, greeting),
        "MaxCapacity": capacity,
        "MaxRetries": 0,
        "Timeout": 5,
        "ExecutionProperty": {"MaxConcurrentRuns": 1},
    }
    assert got == want, f"GetJob must read back the template: {got!r}, want {want!r}"


def _outputs(cfn, stack_id: str) -> dict:
    return {o["OutputKey"]: o.get("OutputValue") for o in _stack(cfn, stack_id).get("Outputs", [])}


def _stop_runs(glue, job: str, runs: list[str], limit: dict) -> None:
    """Teardown: stop a run that has not finished, so it writes nothing after the bucket goes."""
    try:
        live = [r for r in runs if _run_state(glue, job, r) not in _TERMINAL]
    except ClientError as exc:
        if _error(exc) == _NO_RUN:
            return  # the job and its runs are gone
        raise
    if not live:
        return
    failed = glue.batch_stop_job_run(JobName=job, JobRunIds=live).get("Errors")
    if failed:
        raise AssertionError(f"BatchStopJobRun refused {failed!r}")
    _poll(
        None,
        lambda: [_run_state(glue, job, r) for r in live],
        lambda states: all(s in _TERMINAL for s in states),
        cap_s=_remaining(limit),
        what=f"runs {live!r} of {job} to stop",
    )


def _error(exc: ClientError) -> tuple:
    err = exc.response.get("Error", {})
    return err.get("Code"), err.get("Message")


def _run_state(glue, job: str, run_id: str) -> str:
    return glue.get_job_run(JobName=job, RunId=run_id)["JobRun"]["JobRunState"]


def _delete_log_streams(logs, prefix: str) -> None:
    """Teardown: delete the streams named prefix* that Glue wrote into /aws-glue/ log groups.

    The groups are account-shared, so they stay.
    """
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix="/aws-glue/"):
        for group in page["logGroups"]:
            name = group["logGroupName"]
            for streams in logs.get_paginator("describe_log_streams").paginate(
                logGroupName=name, logStreamNamePrefix=prefix
            ):
                for stream in streams.get("logStreams", []):
                    try:
                        logs.delete_log_stream(
                            logGroupName=name, logStreamName=stream["logStreamName"]
                        )
                    except ClientError as exc:
                        if _error(exc) != _NO_STREAM:
                            raise


def _delete_run_log_streams(logs, runs: list[str]) -> None:
    """Teardown: Glue names each run's log streams after its run id."""
    for run_id in runs:
        _delete_log_streams(logs, run_id)


def _empty_bucket(s3, bucket: str) -> None:
    """Delete every object version and delete marker; a bucket already gone is fine."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
    except ClientError as exc:
        if _error(exc) != _NO_BUCKET:
            raise


def _drop_bucket(s3, bucket: str) -> None:
    _empty_bucket(s3, bucket)
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if _error(exc) != _NO_BUCKET:
            raise


def _await_error(ctx, fn, want: tuple[str, str], what: str) -> None:
    """Poll fn until it is refused, then assert the exact (code, message) want.

    A delete reaches every read within seconds, so a call that still succeeds is retried.
    """
    timeout_s = _budget_s(ctx, _PROPAGATE_S)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            got = (err.get("Code"), err.get("Message") or "")
            assert got == want, f"{what}: {got!r}, expected {want!r}"
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended while {what} still succeeded; not graded")
            raise AssertionError(f"{what} still succeeded after {timeout_s:.0f}s: {result!r}")
        time.sleep(2.0)


# ===== stack helpers =====


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    Teardown passes ctx=None and keeps the fixed cap: the runner's deadline does not cover it.
    """
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = None if ctx is None else ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, *, cap_s: float, what: str, interval_s: float = 2.0):
    """Call probe() until done(result) holds and return it; ctx=None (teardown) is not budgeted."""
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended while waiting for {what}; not graded")
            raise AssertionError(f"{what} not reached within {timeout_s:.0f}s; last {last!r}")
        time.sleep(interval_s)


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(ctx, cfn, stack_id: str) -> dict:
    """The stack once no operation (cleanup phase included) is in progress on it."""
    return _poll(
        ctx,
        lambda: _stack(cfn, stack_id),
        lambda s: not s["StackStatus"].endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} settled",
    )


def _physical(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _assert_tracks(cfn, stack_id: str, logical_id: str, expected: str) -> None:
    """CloudFormation's view: the stack resource carries the expected PhysicalResourceId."""
    got = _physical(cfn, stack_id, logical_id)
    assert got == expected, f"the stack must track {logical_id} as {expected!r}, got {got!r}"


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _update(ctx, cfn, stack_id: str, logical_id: str, body: str, **kw) -> list[tuple]:
    """UpdateStack to body, assert UPDATE_COMPLETE and return the update's rows for logical_id.

    A row is (ResourceStatus, ResourceStatusReason, PhysicalResourceId), oldest first.
    """
    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=body, **kw)
    stack = _settle(ctx, cfn, stack_id)
    events = _events(cfn, stack_id)[before:]
    failed = [
        (e["LogicalResourceId"], e.get("ResourceStatusReason"))
        for e in events
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"update ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}; {failed!r}"
    )
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["LogicalResourceId"] == logical_id
    ]


def _in_order(rows: list[tuple], wanted: list[tuple]) -> bool:
    """Whether every wanted row occurs in rows in that order; a None field matches any value."""
    remaining = iter(rows)
    return all(
        any(all(w is None or w == v for w, v in zip(want, row, strict=True)) for row in remaining)
        for want in wanted
    )


def _assert_updated_in_place(rows: list[tuple], physical: str) -> None:
    """The update completed on the same physical id and reported no replacement or delete."""
    assert _in_order(
        rows, [("UPDATE_IN_PROGRESS", None, None), ("UPDATE_COMPLETE", None, physical)]
    ), f"an in-place update must progress and complete on {physical!r}: {rows!r}"
    replacing = [r for r in rows if r[1] == _REPLACING or r[0].startswith("DELETE_")]
    assert replacing == [], f"an in-place update must not replace anything: {replacing!r}"


def _assert_replaced_and_retained(rows: list[tuple], old: str, new: str) -> None:
    """The update reported a replacement, completed on the new id and skipped deleting the old."""
    assert _in_order(
        rows,
        [
            ("UPDATE_IN_PROGRESS", _REPLACING, None),
            ("UPDATE_COMPLETE", None, new),
            ("DELETE_SKIPPED", None, old),
        ],
    ), (
        f"the replacement must report creating a new resource, complete as {new!r} and skip "
        f"deleting {old!r} (UpdateReplacePolicy Retain), in that order: {rows!r}"
    )
    deleted = [r for r in rows if r[0] in ("DELETE_IN_PROGRESS", "DELETE_COMPLETE")]
    assert deleted == [], f"UpdateReplacePolicy Retain must delete nothing: {deleted!r}"


def _delete_and_confirm(ctx, cfn, stack_id: str) -> None:
    """DeleteStack by StackId and assert it reaches DELETE_COMPLETE."""
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        ctx,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} deleted",
    )
    assert final == "DELETE_COMPLETE", (
        f"DeleteStack ended {final!r}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
    )


def _remaining(limit: dict) -> float:
    """Seconds left of the one teardown deadline, which starts at the first teardown wait."""
    deadline = limit.setdefault("at", time.monotonic() + _TEARDOWN_CAP_S)
    return max(1.0, deadline - time.monotonic())


def _delete_stack(cfn, stack_name: str, limit: dict) -> None:
    """Teardown: delete the stack by its StackId and wait; DELETE_FAILED or a timeout raises."""
    try:
        stack_id = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {stack_name} does not exist":
            return
        raise
    status = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_remaining(limit),
        what=f"stack {stack_id} settled before teardown",
    )
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
        cap_s=_remaining(limit),
        what=f"stack {stack_id} deleted",
    )
    if final != "DELETE_COMPLETE":
        raise AssertionError(
            f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
