"""create-workflow-untrusted-execution-role-access-denied-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-workflow-untrusted-execution-role-access-denied-rejected"
GROUP = "overly-permissive"
SERVICES = ["mwaa-serverless"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateWorkflow accepts a role airflow-serverless cannot assume, StartWorkflowRun then fails with
    ValidationException "... could not be assumed ..." and records no run, and after switching to a
    trusted role a run starts and is listed.
    """
    mwaa = ctx.client("mwaa-serverless")
    bucket = _create_dag_bucket(ctx, "untrust")
    key = "dags/sim2real.yaml"
    _put_dag(ctx, bucket, key, _simple_dag_yaml("sim2real_dag", "echo hello"))

    untrusted_role_arn = _create_execution_role(ctx, suffix="untrust-bad", trusted=False)
    name = ctx.unique_name("sim2real-mwaas-untrust-")

    created = _create_workflow_retrying(
        ctx,
        mwaa,
        Name=name,
        DefinitionS3Location={"Bucket": bucket, "ObjectKey": key},
        RoleArn=untrusted_role_arn,
        Tags={"created-by": "sim2real"},
    )
    workflow_arn = created["WorkflowArn"]
    ctx.on_cleanup(lambda: mwaa.delete_workflow(WorkflowArn=workflow_arn))
    # control: CreateWorkflow itself did NOT reject the untrusted role -- it is READY.
    assert mwaa.get_workflow(WorkflowArn=workflow_arn)["WorkflowStatus"] == "READY", (
        "CreateWorkflow with an untrusted RoleArn did not leave the workflow READY"
    )

    code, message = _error_code_and_message(lambda: mwaa.start_workflow_run(WorkflowArn=workflow_arn))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message}"
    assert message == "Workflow execution role could not be assumed by the airflow-serverless service", (
        f"unexpected ValidationException message: {message!r}"
    )

    runs = mwaa.list_workflow_runs(WorkflowArn=workflow_arn)["WorkflowRuns"]
    assert runs == [], f"StartWorkflowRun was rejected but a run was recorded anyway: {runs!r}"

    # positive control: point the same workflow at a properly-trusted role, then run succeeds
    trusted_role_arn = _create_execution_role(ctx, suffix="untrust-good", trusted=True)
    mwaa.update_workflow(
        WorkflowArn=workflow_arn,
        DefinitionS3Location={"Bucket": bucket, "ObjectKey": key},
        RoleArn=trusted_role_arn,
    )
    started = _start_workflow_run_retrying(ctx, mwaa, workflow_arn)
    run_id = started["RunId"]
    assert run_id, f"StartWorkflowRun with a trusted role did not return a RunId: {started!r}"
    ctx.on_cleanup(lambda: _try_stop(mwaa, workflow_arn, run_id))

    # terminal read: an INDEPENDENT operation (ListWorkflowRuns) confirms the trusted-role run
    # actually landed, not just that StartWorkflowRun's own response echoed a RunId.
    seen_ids = {r["RunId"] for r in mwaa.list_workflow_runs(WorkflowArn=workflow_arn)["WorkflowRuns"]}
    assert run_id in seen_ids, (
        f"trusted-role run {run_id!r} did not appear in ListWorkflowRuns: {seen_ids!r}"
    )


def _try_stop(mwaa, workflow_arn, run_id):
    try:
        mwaa.stop_workflow_run(WorkflowArn=workflow_arn, RunId=run_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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


_TRUST_SERVICE = "airflow-serverless.amazonaws.com"


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(
        f"expected the call to be refused for an untrusted execution role, but it SUCCEEDED: {result!r}"
    )


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


def _create_execution_role(ctx, suffix, trusted):
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

