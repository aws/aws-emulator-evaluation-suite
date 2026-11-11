"""start-workflow-run-nonexistent-workflow-version-not-found-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-workflow-run-nonexistent-workflow-version-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["mwaa-serverless"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartWorkflowRun pinned to a well-formed but never-created WorkflowVersion is rejected with
    ResourceNotFoundException, no run is recorded, and starting without a version pin (using the
    real latest version) succeeds (control)."""
    mwaa = ctx.client("mwaa-serverless")
    bucket = _create_dag_bucket(ctx, "badver")
    role_arn = _create_execution_role(ctx, suffix="badver")
    key = "dags/sim2real.yaml"
    _put_dag(ctx, bucket, key, _simple_dag_yaml("sim2real_dag", "echo hello"))

    name = ctx.unique_name("sim2real-mwaas-badver-")
    created = _create_workflow_retrying(
        ctx,
        mwaa,
        Name=name,
        DefinitionS3Location={"Bucket": bucket, "ObjectKey": key},
        RoleArn=role_arn,
        Tags={"Owner": "behavioral-suite"},
    )
    workflow_arn = created["WorkflowArn"]
    ctx.on_cleanup(lambda: mwaa.delete_workflow(WorkflowArn=workflow_arn))

    # Warm up: a freshly-created role can take a few seconds to become assumable by
    # airflow-serverless.amazonaws.com. Establish a successful run first so a later
    # ValidationException on the bad-version attempt can only be attributed to the bad
    # version, never to role-assumption propagation lag (this doubles as the positive control).
    warm = _start_workflow_run_retrying(ctx, mwaa, workflow_arn)
    ctx.on_cleanup(lambda: _try_stop(mwaa, workflow_arn, warm["RunId"]))
    assert warm["RunId"], "positive control: warm-up StartWorkflowRun should return a RunId"

    runs_before = mwaa.list_workflow_runs(WorkflowArn=workflow_arn)["WorkflowRuns"]

    fake_version = "00000000000000000000000000000000"[:32]
    code, message = _error(
        lambda: mwaa.start_workflow_run(WorkflowArn=workflow_arn, WorkflowVersion=fake_version)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a well-formed but never-created "
        f"WorkflowVersion, got {code!r}"
    )
    assert message == "Workflow version not found", f"unexpected ResourceNotFoundException message: {message!r}"

    # effect absent: the rejected attempt against a nonexistent version recorded no new run
    runs_after = mwaa.list_workflow_runs(WorkflowArn=workflow_arn)["WorkflowRuns"]
    assert len(runs_after) == len(runs_before), (
        f"rejected StartWorkflowRun must not record a new run: "
        f"before={len(runs_before)} after={len(runs_after)}"
    )


_TERMINAL_RUN_STATES = {"SUCCESS", "FAILED", "TIMEOUT", "STOPPED"}


def _try_stop(mwaa, workflow_arn, run_id, *, timeout_s=300.0, interval_s=5.0):
    """Stop the run and wait for a terminal state, because DeleteWorkflow is refused while a
    run is still in progress."""
    try:
        mwaa.stop_workflow_run(WorkflowArn=workflow_arn, RunId=run_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = mwaa.get_workflow_run(WorkflowArn=workflow_arn, RunId=run_id)["RunDetail"]["RunState"]
        if state in _TERMINAL_RUN_STATES:
            return
        time.sleep(interval_s)
    raise TimeoutError(f"run {run_id} did not reach a terminal state within {timeout_s}s")


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
            if err["Code"] == "ValidationException" and "assumed" in msg:
                last_err = e
                time.sleep(interval_s)
                continue
            raise
    raise last_err


_TRUST_SERVICE = "airflow-serverless.amazonaws.com"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection but the call SUCCEEDED and returned {result!r}")


def _bucket_name(ctx, suffix):
    return ctx.unique_name(f"sim2real-mwaas-{suffix}-").lower().replace("_", "-")[:63].rstrip("-")


def _create_dag_bucket(ctx, suffix):
    s3 = ctx.client("s3")
    name = _bucket_name(ctx, suffix)
    kwargs = {}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "Owner", "Value": "behavioral-suite"}]})
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
        Tags=[{"Key": "Owner", "Value": "behavioral-suite"}],
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
