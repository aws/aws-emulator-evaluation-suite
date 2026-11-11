"""workflow-run-status-progresses-through-lifecycle-states."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "workflow-run-status-progresses-through-lifecycle-states"
GROUP = "state"
SERVICES = ["mwaa-serverless"]

_PRE_RUN_STATES = {"STARTING", "QUEUED"}
_TERMINAL_RUN_STATES = {"SUCCESS", "FAILED", "TIMEOUT", "STOPPED"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartWorkflowRun reports a pre-run state (STARTING/QUEUED), the run reaches SUCCESS, and
    its own StartedOn/CompletedOn span at least 15 s of a single 25-second sleep task, proving real
    execution rather than an instant completion (intermediate states are not graded)."""
    mwaa = ctx.client("mwaa-serverless")
    bucket = _create_dag_bucket(ctx, "lifecycle")
    role_arn = _create_execution_role(ctx, suffix="lifecycle")
    key = "dags/lifecycle.yaml"
    _put_dag(ctx, bucket, key, _simple_dag_yaml("sim2real_dag", "sleep 25"))

    name = ctx.unique_name("sim2real-mwaas-lifecycle-")
    created = _create_workflow_retrying(
        ctx,
        mwaa,
        Name=name,
        DefinitionS3Location={"Bucket": bucket, "ObjectKey": key},
        RoleArn=role_arn,
        Tags={"created-by": "sim2real"},
    )
    workflow_arn = created["WorkflowArn"]
    ctx.on_cleanup(lambda: mwaa.delete_workflow(WorkflowArn=workflow_arn))

    started = _start_workflow_run_retrying(ctx, mwaa, workflow_arn)
    run_id = started["RunId"]
    assert started["Status"] in _PRE_RUN_STATES, (
        f"expected a pre-run status in {_PRE_RUN_STATES}, got {started['Status']!r}"
    )

    t0 = time.monotonic()
    observed = []
    timeline = []
    left = ctx.time_left()
    deadline = t0 + (600.0 if left is None else min(600.0, left))
    last_detail = None
    while time.monotonic() < deadline:
        last_detail = mwaa.get_workflow_run(WorkflowArn=workflow_arn, RunId=run_id)["RunDetail"]
        state = last_detail["RunState"]
        timeline.append((round(time.monotonic() - t0, 1), state))
        if not observed or observed[-1] != state:
            observed.append(state)
        if state in _TERMINAL_RUN_STATES:
            break
        time.sleep(2.0)
    else:
        raise AssertionError(f"run never reached a terminal state; observed sequence={observed!r}")

    assert observed[-1] == "SUCCESS", observed

    started_on = last_detail["StartedOn"]
    completed_on = last_detail["CompletedOn"]
    assert started_on is not None and completed_on is not None, last_detail
    elapsed_s = (completed_on - started_on).total_seconds()
    assert elapsed_s >= 15.0, (
        f"run completed in {elapsed_s}s per its own StartedOn/CompletedOn, too fast for the "
        f"25-second sleep task -- expected genuine execution, not an instant fake completion; "
        f"timeline={timeline!r}"
    )


# ===== helpers =====
_TRUST_SERVICE = "airflow-serverless.amazonaws.com"


def _bucket_name(ctx, suffix):
    return ctx.unique_name(f"sim2real-mwaas-{suffix}-").lower().replace("_", "-")[:63].rstrip("-")


def _create_dag_bucket(ctx, suffix):
    s3 = ctx.client("s3")
    name = _bucket_name(ctx, suffix)
    kwargs = {}
    # us-east-1 is S3's original region and CreateBucket rejects an explicit LocationConstraint
    # for it; every other region requires one.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "created-by", "Value": "sim2real"}]})
    s3.put_public_access_block(
        Bucket=name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})

    def _cleanup():
        versions = s3.list_object_versions(Bucket=name)
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in versions.get("Versions", [])]
        objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in versions.get("DeleteMarkers", [])]
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _put_dag(ctx, bucket, key, yaml_text):
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=yaml_text.encode("utf-8"))


def _simple_dag_yaml(dag_id, bash_command):
    return (
        f"{dag_id}:\n"
        f'  start_date: "2024-01-01"\n'
        f"  schedule: null\n"
        f"  tasks:\n"
        f"    only_task:\n"
        f"      operator: airflow.providers.standard.operators.bash.BashOperator\n"
        f'      bash_command: "{bash_command}"\n'
    )


def _create_execution_role(ctx, suffix, trusted=True):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-mwaas-{suffix}-")
    principal_service = _TRUST_SERVICE if trusted else "lambda.amazonaws.com"
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": principal_service}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "created-by", "Value": "sim2real"}],
    )["Role"]
    policy_arns = (
        "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
        "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
    )
    for policy_arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        for policy_arn in policy_arns:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_workflow_retrying(ctx, mwaa, *, timeout_s=90.0, interval_s=5.0, **kwargs):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return mwaa.create_workflow(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last_err = e
            time.sleep(interval_s)
    raise last_err


def _start_workflow_run_retrying(ctx, mwaa, workflow_arn, *, timeout_s=90.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return mwaa.start_workflow_run(WorkflowArn=workflow_arn)
        except ClientError as e:
            err = e.response["Error"]
            msg = err.get("Message", "")
            if err["Code"] == "ValidationException" and "assum" in msg.lower():
                last_err = e
                time.sleep(interval_s)
                continue
            raise
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
