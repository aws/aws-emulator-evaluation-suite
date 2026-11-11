"""workflow-run-success-end-to-end."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "workflow-run-success-end-to-end"
GROUP = "data-plane"
SERVICES = ["mwaa-serverless"]

_TERMINAL_RUN_STATES = {"SUCCESS", "FAILED", "TIMEOUT", "STOPPED"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A workflow run with two independent BashOperator tasks ends SUCCESS with CompletedOn set, and
    ListTaskInstances and GetTaskInstance report both tasks SUCCESS with start and end times.
    """
    mwaa = ctx.client("mwaa-serverless")
    bucket = _create_dag_bucket(ctx, "success")
    role_arn = _create_execution_role(ctx, suffix="success")
    key = "dags/two_task.yaml"
    _put_dag(ctx, bucket, key, _two_task_dag_yaml("sim2real_dag"))

    name = ctx.unique_name("sim2real-mwaas-success-")
    created = _create_workflow_retrying(
        ctx,
        mwaa,
        Name=name,
        DefinitionS3Location={"Bucket": bucket, "ObjectKey": key},
        RoleArn=role_arn,
        Tags={"sim2real": CHECK},
    )
    workflow_arn = created["WorkflowArn"]
    ctx.on_cleanup(lambda: mwaa.delete_workflow(WorkflowArn=workflow_arn))

    started = _start_workflow_run_retrying(mwaa, workflow_arn)
    run_id = started["RunId"]

    final = _wait_run_terminal(mwaa, workflow_arn, run_id, timeout_s=900.0)
    run_state = final["RunDetail"]["RunState"]
    task_ids = final["RunDetail"]["TaskInstances"]
    details = {
        tid: mwaa.get_task_instance(WorkflowArn=workflow_arn, RunId=run_id, TaskInstanceId=tid)
        for tid in task_ids
    }
    assert run_state == "SUCCESS", _diagnose_failed_run(ctx, mwaa, workflow_arn, final, details)
    completed_on = final["RunDetail"]["CompletedOn"]
    assert completed_on is not None, f"expected CompletedOn to be set on a terminal run, got {completed_on!r}"
    assert len(task_ids) == 2, f"expected 2 task instances for the two-task DAG, got {len(task_ids)}: {task_ids!r}"

    listed = mwaa.list_task_instances(WorkflowArn=workflow_arn, RunId=run_id)["TaskInstances"]
    listed_ids = {t["TaskInstanceId"] for t in listed}
    assert listed_ids == set(task_ids), (
        f"ListTaskInstances {listed_ids!r} does not match the run's own TaskInstances {set(task_ids)!r}"
    )
    for t in listed:
        assert t["Status"] == "SUCCESS", f"task instance {t['TaskInstanceId']!r} status {t['Status']!r}, expected SUCCESS"

    for task_instance_id, detail in details.items():
        assert detail["Status"] == "SUCCESS", f"task instance {task_instance_id!r} status {detail['Status']!r}, expected SUCCESS"
        assert detail["StartedAt"] is not None, f"task instance {task_instance_id!r} has no StartedAt: {detail!r}"
        assert detail["EndedAt"] is not None, f"task instance {task_instance_id!r} has no EndedAt: {detail!r}"


_TRUST_SERVICE = "airflow-serverless.amazonaws.com"


def _bucket_name(ctx, suffix):
    return ctx.unique_name(f"sim2real-mwaas-{suffix}-").lower().replace("_", "-")[:63].rstrip("-")


def _create_dag_bucket(ctx, suffix):
    s3 = ctx.client("s3")
    name = _bucket_name(ctx, suffix)
    kwargs = {}
    # us-east-1 is S3's default region and CreateBucket rejects an explicit LocationConstraint for it.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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


def _two_task_dag_yaml(dag_id):
    return (
        f"{dag_id}:\n"
        f'  start_date: "2024-01-01"\n'
        f"  schedule: null\n"
        f"  tasks:\n"
        f"    first_task:\n"
        f"      operator: airflow.providers.standard.operators.bash.BashOperator\n"
        f'      bash_command: "echo sim2real-first"\n'
        f"    second_task:\n"
        f"      operator: airflow.providers.standard.operators.bash.BashOperator\n"
        f'      bash_command: "echo sim2real-second"\n'
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _start_workflow_run_retrying(mwaa, workflow_arn, *, timeout_s=90.0, interval_s=5.0):
    """A workflow created moments ago can 400 on its first run: the execution role's trust
    policy has not yet propagated to airflow-serverless, which reports it as a validation
    error rather than an access-denied one. Retry only that specific, named cause."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return mwaa.start_workflow_run(WorkflowArn=workflow_arn)
        except ClientError as e:
            err = e.response["Error"]
            if err["Code"] != "ValidationException" or "could not be assumed" not in err.get("Message", ""):
                raise
            last_err = e
            time.sleep(interval_s)
    raise last_err


def _diagnose_failed_run(ctx, mwaa, workflow_arn, final, details):
    """Pull the error-level task logs so a non-SUCCESS run fails with a reason, not just a state."""
    log_group = mwaa.get_workflow(WorkflowArn=workflow_arn)["LoggingConfiguration"]["LogGroupName"]
    logs = ctx.client("logs")
    tails = {}
    for tid, d in details.items():
        stream = d.get("LogStream")
        if not stream:
            tails[tid] = "<no LogStream>"
            continue
        try:
            events = logs.get_log_events(logGroupName=log_group, logStreamName=stream, limit=50)
            errors = []
            for e in events["events"]:
                try:
                    parsed = json.loads(e["message"])
                except ValueError:
                    continue
                if parsed.get("level") == "error":
                    errors.append({k: parsed.get(k) for k in ("event", "dag_id", "exception")})
            tails[tid] = json.dumps(errors)
        except Exception as e:  # noqa: BLE001 — diagnostic only, feeds the assertion message
            tails[tid] = f"<log read failed: {e!r}>"
    return (
        f"expected RunState=SUCCESS, got {final['RunDetail']['RunState']!r}; ErrorMessage="
        f"{final['RunDetail'].get('ErrorMessage')!r}; log_group={log_group!r}; task logs=\n"
        + "\n---\n".join(f"{tid}: {tail}" for tid, tail in tails.items())
    )


def _wait_run_terminal(mwaa, workflow_arn, run_id, timeout_s=900.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = mwaa.get_workflow_run(WorkflowArn=workflow_arn, RunId=run_id)
        if last["RunDetail"]["RunState"] in _TERMINAL_RUN_STATES:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"run did not reach a terminal state within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
