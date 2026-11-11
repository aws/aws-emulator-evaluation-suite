"""update-workflow-creates-new-version-flips-latest."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-workflow-creates-new-version-flips-latest"
GROUP = "state"
SERVICES = ["mwaa-serverless"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateWorkflow mints a new immutable WorkflowVersion and flips IsLatestVersion."""
    mwaa = ctx.client("mwaa-serverless")
    bucket = _create_dag_bucket(ctx, "upwf")
    role_arn = _create_execution_role(ctx, suffix="upwf")
    key_v1 = "dags/v1.yaml"
    key_v2 = "dags/v2.yaml"
    _put_dag(ctx, bucket, key_v1, _simple_dag_yaml("sim2real_dag", "echo v1"))
    _put_dag(ctx, bucket, key_v2, _simple_dag_yaml("sim2real_dag", "echo v2"))

    name = ctx.unique_name("sim2real-mwaas-upwf-")
    created = _create_workflow_retrying(
        ctx,
        mwaa,
        Name=name,
        DefinitionS3Location={"Bucket": bucket, "ObjectKey": key_v1},
        RoleArn=role_arn,
        Tags={"sim2real-check": CHECK},
    )
    workflow_arn = created["WorkflowArn"]
    ctx.on_cleanup(lambda: mwaa.delete_workflow(WorkflowArn=workflow_arn))
    v1_version = created["WorkflowVersion"]
    # UpdateWorkflow's own response carries no IsLatestVersion field at all (unlike
    # CreateWorkflow's); ListWorkflowVersions is the independent read used to check latest-ness
    # both before and after the update.
    v1_list = mwaa.list_workflow_versions(WorkflowArn=workflow_arn)["WorkflowVersions"]
    assert {v["WorkflowVersion"]: v["IsLatestVersion"] for v in v1_list} == {v1_version: True}, (
        f"expected only {v1_version} latest right after CreateWorkflow, got {v1_list}"
    )

    updated = mwaa.update_workflow(
        WorkflowArn=workflow_arn,
        DefinitionS3Location={"Bucket": bucket, "ObjectKey": key_v2},
        RoleArn=role_arn,
    )
    v2_version = updated["WorkflowVersion"]

    assert v2_version != v1_version, (
        f"UpdateWorkflow returned the same WorkflowVersion {v2_version!r} as CreateWorkflow"
    )
    # WorkflowVersion is a fixed-length smithy.api#length(32,32) opaque id, not a guess.
    assert len(v2_version) == 32, f"expected a 32-char WorkflowVersion, got {v2_version!r}"

    versions = mwaa.list_workflow_versions(WorkflowArn=workflow_arn)["WorkflowVersions"]
    by_id = {v["WorkflowVersion"]: v for v in versions}
    assert by_id[v1_version]["IsLatestVersion"] is False, (
        f"expected {v1_version} to no longer be latest after the update, got {by_id[v1_version]}"
    )
    assert by_id[v2_version]["IsLatestVersion"] is True, (
        f"expected {v2_version} to be latest after the update, got {by_id[v2_version]}"
    )

    latest = mwaa.get_workflow(WorkflowArn=workflow_arn)
    assert latest["WorkflowVersion"] == v2_version, (
        f"GetWorkflow with no WorkflowVersion pin should resolve to latest {v2_version!r}, "
        f"got {latest['WorkflowVersion']!r}"
    )
    assert latest["DefinitionS3Location"]["ObjectKey"] == key_v2, (
        f"expected GetWorkflow's default resolution to reflect the updated definition {key_v2!r}, "
        f"got {latest['DefinitionS3Location']['ObjectKey']!r}"
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
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
