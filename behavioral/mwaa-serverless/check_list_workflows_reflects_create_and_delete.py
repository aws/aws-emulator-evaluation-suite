"""list-workflows-reflects-create-and-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-workflows-reflects-create-and-delete"
GROUP = "state"
SERVICES = ["mwaa-serverless"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created workflow appears in ListWorkflows; after DeleteWorkflow it no longer does."""
    mwaa = ctx.client("mwaa-serverless")
    bucket = _create_dag_bucket(ctx, "lwfs")
    role_arn = _create_execution_role(ctx, suffix="lwfs")
    key = "dags/sim2real.yaml"
    _put_dag(ctx, bucket, key, _simple_dag_yaml("sim2real_dag", "echo hello"))

    name = ctx.unique_name("sim2real-mwaas-lwfs-")
    created = _create_workflow_retrying(
        ctx,
        mwaa,
        Name=name,
        DefinitionS3Location={"Bucket": bucket, "ObjectKey": key},
        RoleArn=role_arn,
        Tags={"created-by": "sim2real"},
    )
    workflow_arn = created["WorkflowArn"]

    found_after_create = _find_workflow(mwaa, workflow_arn)
    assert found_after_create is not None, f"expected {workflow_arn} in ListWorkflows after CreateWorkflow, found nothing"

    mwaa.delete_workflow(WorkflowArn=workflow_arn)

    # Deletion is asynchronous (WorkflowStatus: READY -> DELETING -> removed); poll ListWorkflows
    # until the entry drops out instead of asserting on the very next page.
    deadline = time.monotonic() + 180.0
    found = _find_workflow(mwaa, workflow_arn)
    while found is not None and time.monotonic() < deadline:
        time.sleep(5.0)
        found = _find_workflow(mwaa, workflow_arn)
    assert found is None, f"workflow still listed after delete: {found}"


def _find_workflow(mwaa, workflow_arn):
    token = None
    while True:
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = mwaa.list_workflows(**kwargs)
        for wf in page.get("Workflows", []):
            if wf["WorkflowArn"] == workflow_arn:
                return wf
        token = page.get("NextToken")
        if not token:
            return None


_TRUST_SERVICE = "airflow-serverless.amazonaws.com"


def _bucket_name(ctx, suffix):
    return ctx.unique_name(f"sim2real-mwaas-{suffix}-").lower().replace("_", "-")[:63].rstrip("-")


def _create_dag_bucket(ctx, suffix):
    s3 = ctx.client("s3")
    name = _bucket_name(ctx, suffix)
    kwargs = {}
    # S3 quirk, not a region pin: us-east-1 is the API's implicit default and rejects an explicit
    # LocationConstraint of "us-east-1" on CreateBucket, so it must be omitted there specifically.
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
