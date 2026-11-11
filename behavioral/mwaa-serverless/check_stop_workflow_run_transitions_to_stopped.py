"""stop-workflow-run-transitions-to-stopped."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stop-workflow-run-transitions-to-stopped"
GROUP = "data-plane"
SERVICES = ["mwaa-serverless"]

_NON_STARTING_STATES = {"RUNNING", "QUEUED", "SUCCESS", "FAILED", "TIMEOUT", "STOPPING", "STOPPED"}
_TERMINAL_RUN_STATES = {"SUCCESS", "FAILED", "TIMEOUT", "STOPPED"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopWorkflowRun on an in-flight run drives it to a terminal STOPPED state (not left running,
    not silently ignored). Provisioning the real workflow (S3 DAG + execution role) is slow on real
    AWS and is done there all the same, exactly as it is against an emulator."""
    mwaa = ctx.client("mwaa-serverless")
    bucket = _create_dag_bucket(ctx, "stoprun")
    role_arn = _create_execution_role(ctx, suffix="stoprun")
    key = "dags/sleeper.yaml"
    _put_dag(ctx, bucket, key, _simple_dag_yaml("sim2real_sleep_dag", "sleep 240"))

    name = ctx.unique_name("sim2real-mwaas-stoprun-")
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

    started = _start_workflow_run_retrying(mwaa, WorkflowArn=workflow_arn)
    run_id = started["RunId"]

    # wait until the run has moved past pure queueing so a Stop has something in-flight to stop
    in_flight = _poll_until(
        lambda: mwaa.get_workflow_run(WorkflowArn=workflow_arn, RunId=run_id),
        lambda resp: resp["RunDetail"]["RunState"] in _NON_STARTING_STATES,
        timeout_s=300.0,
        interval_s=5.0,
    )
    if in_flight["RunDetail"]["RunState"] in _TERMINAL_RUN_STATES:
        raise AssertionError(
            "run reached a terminal state before StopWorkflowRun could be issued: "
            f"{in_flight['RunDetail']['RunState']}"
        )

    stopped = mwaa.stop_workflow_run(WorkflowArn=workflow_arn, RunId=run_id)
    assert stopped["Status"] in ("STOPPING", "STOPPED"), (
        f"expected StopWorkflowRun to report STOPPING or STOPPED, got {stopped['Status']!r}"
    )

    final = _poll_until(
        lambda: mwaa.get_workflow_run(WorkflowArn=workflow_arn, RunId=run_id),
        lambda resp: resp["RunDetail"]["RunState"] in _TERMINAL_RUN_STATES,
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert final["RunDetail"]["RunState"] == "STOPPED", (
        "expected the run to settle in STOPPED after StopWorkflowRun, got "
        f"{final['RunDetail']['RunState']!r}"
    )


_TRUST_SERVICE = "airflow-serverless.amazonaws.com"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _bucket_name(ctx, suffix):
    return ctx.unique_name(f"sim2real-mwaas-{suffix}-").lower().replace("_", "-")[:63].rstrip("-")


def _create_dag_bucket(ctx, suffix):
    s3 = ctx.client("s3")
    name = _bucket_name(ctx, suffix)
    kwargs = {}
    # us-east-1 is S3's own default region and rejects an explicit LocationConstraint for itself
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


def _start_workflow_run_retrying(mwaa, *, timeout_s=90.0, interval_s=5.0, **kwargs):
    """CreateWorkflow only validates the role's ARN shape; StartWorkflowRun is where the service
    actually calls sts:AssumeRole, so a freshly-created trust policy can still be propagating."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return mwaa.start_workflow_run(**kwargs)
        except ClientError as e:
            error = e.response["Error"]
            if error["Code"] != "ValidationException" or "could not be assumed" not in error["Message"]:
                raise
            last_err = e
            time.sleep(interval_s)
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
