"""list-workflow-runs-reflects-multiple-runs."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-workflow-runs-reflects-multiple-runs"
GROUP = "data-plane"
SERVICES = ["mwaa-serverless"]

_TERMINAL_RUN_STATES = {"SUCCESS", "FAILED", "TIMEOUT", "STOPPED"}


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two on-demand runs of one workflow appear in ListWorkflowRuns with distinct RunIds and its
    WorkflowArn, and GetWorkflowRun reports each as ON_DEMAND.
    """
    mwaa = ctx.client("mwaa-serverless")
    bucket = _create_dag_bucket(ctx, "multirun")
    role_arn = _create_execution_role(ctx, suffix="multirun")
    key = "dags/sim2real.yaml"
    _put_dag(ctx, bucket, key, _simple_dag_yaml("sim2real_dag", "echo hello"))

    name = ctx.unique_name("sim2real-mwaas-multirun-")
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

    run_id_1 = _start_workflow_run_retrying(ctx, mwaa, workflow_arn)["RunId"]
    run_id_2 = _start_workflow_run_retrying(ctx, mwaa, workflow_arn)["RunId"]
    assert run_id_1 != run_id_2, f"expected two distinct RunIds, got {run_id_1!r} twice"

    details = {run_id: _wait_run_terminal(mwaa, workflow_arn, run_id, timeout_s=900.0) for run_id in (run_id_1, run_id_2)}
    for run_id, detail in details.items():
        assert detail["RunType"] == "ON_DEMAND", (
            f"run {run_id!r}: expected GetWorkflowRun RunType ON_DEMAND, got {detail['RunType']!r}"
        )

    runs = mwaa.list_workflow_runs(WorkflowArn=workflow_arn)["WorkflowRuns"]
    seen_ids = {r["RunId"] for r in runs}
    assert {run_id_1, run_id_2} <= seen_ids, (
        f"expected ListWorkflowRuns to include both {run_id_1!r} and {run_id_2!r}, got {seen_ids!r}"
    )
    for r in runs:
        if r["RunId"] in (run_id_1, run_id_2):
            assert r["WorkflowArn"] == workflow_arn, (
                f"run {r['RunId']!r}: expected WorkflowArn {workflow_arn!r}, got {r['WorkflowArn']!r}"
            )
            assert r["RunDetailSummary"]["Status"] == details[r["RunId"]]["RunDetail"]["RunState"], (
                f"run {r['RunId']!r}: ListWorkflowRuns Status {r['RunDetailSummary']['Status']!r} "
                f"disagrees with GetWorkflowRun RunState {details[r['RunId']]['RunDetail']['RunState']!r}"
            )


_TRUST_SERVICE = "airflow-serverless.amazonaws.com"


def _bucket_name(ctx, suffix):
    return ctx.unique_name(f"sim2real-mwaas-{suffix}-").lower().replace("_", "-")[:63].rstrip("-")


def _create_dag_bucket(ctx, suffix):
    s3 = ctx.client("s3")
    name = _bucket_name(ctx, suffix)
    kwargs = {}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
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
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "created-by", "Value": "sim2real"}]})

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
