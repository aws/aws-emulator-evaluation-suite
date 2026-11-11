"""delete-workflow-removes-resource."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-workflow-removes-resource"
GROUP = "lifecycle"
SERVICES = ["mwaa-serverless"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteWorkflow permanently removes the workflow; a subsequent GetWorkflow is NotFound."""
    mwaa = ctx.client("mwaa-serverless")
    bucket = _create_dag_bucket(ctx, "delwf")
    role_arn = _create_execution_role(ctx, suffix="delwf")
    key = "dags/sim2real.yaml"
    _put_dag(ctx, bucket, key, _simple_dag_yaml("sim2real_dag", "echo hello"))

    name = ctx.unique_name("sim2real-mwaas-delwf-")
    created = _create_workflow_retrying(
        ctx,
        mwaa,
        Name=name,
        DefinitionS3Location={"Bucket": bucket, "ObjectKey": key},
        RoleArn=role_arn,
        Tags={"created-by": "sim2real"},
    )
    workflow_arn = created["WorkflowArn"]

    # sanity: exists before delete
    mwaa.get_workflow(WorkflowArn=workflow_arn)

    mwaa.delete_workflow(WorkflowArn=workflow_arn)

    # Deletion is asynchronous (WorkflowStatus: READY -> DELETING -> removed); poll GetWorkflow
    # until it reports ResourceNotFoundException instead of asserting the very next call.
    code, message = _poll_get_until_gone(mwaa, workflow_arn, timeout_s=180.0, interval_s=5.0)
    assert code == "ResourceNotFoundException", f"workflow was never removed, last GetWorkflow outcome: {code!r}"
    assert message == "Resource not found", f"unexpected ResourceNotFoundException message: {message!r}"

    # the dead id is also unusable for a mutation: a second delete must not silently succeed
    redelete_code, redelete_message = _error(lambda: mwaa.delete_workflow(WorkflowArn=workflow_arn))
    assert redelete_code == "ResourceNotFoundException", (
        f"delete on an already-deleted workflow returned {redelete_code!r}, want ResourceNotFoundException"
    )
    assert redelete_message == "Resource not found", (
        f"unexpected ResourceNotFoundException message on re-delete: {redelete_message!r}"
    )


def _poll_get_until_gone(mwaa, workflow_arn, *, timeout_s, interval_s):
    """Poll GetWorkflow until it is refused; return that refusal's (code, message). Raises when
    the workflow is still readable at the deadline."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = mwaa.get_workflow(WorkflowArn=workflow_arn).get("WorkflowStatus")
        except ClientError as e:
            err = e.response["Error"]
            return err.get("Code"), err.get("Message")
        time.sleep(interval_s)
    raise AssertionError(
        f"workflow was never removed: GetWorkflow still succeeds after {timeout_s}s "
        f"(last WorkflowStatus {last_status!r})"
    )


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
