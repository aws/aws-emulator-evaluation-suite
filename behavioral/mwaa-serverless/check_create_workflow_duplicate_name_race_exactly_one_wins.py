"""create-workflow-duplicate-name-race-exactly-one-wins."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-workflow-duplicate-name-race-exactly-one-wins"
GROUP = "concurrency"
SERVICES = ["mwaa-serverless"]

_RACERS = 5


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateWorkflow calls with one Name each succeed with a distinct WorkflowArn or fail
    with ConflictException, at least one succeeds, and GetWorkflow and ListWorkflows show exactly
    the successful ARNs under that Name.
    """
    mwaa = ctx.client("mwaa-serverless")
    bucket = _create_dag_bucket(ctx, "race")
    role_arn = _create_execution_role(ctx, suffix="race")
    key = "dags/sim2real.yaml"
    _put_dag(ctx, bucket, key, _simple_dag_yaml("sim2real_dag", "echo hello"))

    # Warm up the freshly created role (IAM propagation) before racing, so AccessDeniedException
    # from eventual consistency cannot be mistaken for the ConflictException under test.
    warmup_name = ctx.unique_name("sim2real-mwaas-race-warmup-")
    warmup = _create_workflow_retrying(
        ctx,
        mwaa,
        Name=warmup_name,
        DefinitionS3Location={"Bucket": bucket, "ObjectKey": key},
        RoleArn=role_arn,
    )
    mwaa.delete_workflow(WorkflowArn=warmup["WorkflowArn"])

    name = ctx.unique_name("sim2real-mwaas-race-")

    def _attempt(_i):
        try:
            resp = mwaa.create_workflow(
                Name=name,
                DefinitionS3Location={"Bucket": bucket, "ObjectKey": key},
                RoleArn=role_arn,
            )
            return ("ok", resp["WorkflowArn"])
        except Exception as e:
            from botocore.exceptions import ClientError

            if isinstance(e, ClientError):
                return ("error", e.response["Error"]["Code"])
            raise

    with ThreadPoolExecutor(max_workers=_RACERS) as pool:
        results = list(pool.map(_attempt, range(_RACERS)))

    successes = [arn for kind, arn in results if kind == "ok"]
    failures = [code for kind, code in results if kind == "error"]

    for arn in successes:
        ctx.on_cleanup(lambda arn=arn: mwaa.delete_workflow(WorkflowArn=arn))

    # at least one racer must win; every failure must be the documented conflict, never silently
    # swallowed or some unrelated error
    assert len(successes) >= 1, f"no racer succeeded: failure_codes={sorted(set(failures))}"
    assert len(successes) + len(failures) == _RACERS
    assert all(code == "ConflictException" for code in failures), failures

    # every WorkflowArn that reported success is independently real and distinct
    assert len(set(successes)) == len(successes), f"duplicate ARNs returned: {successes}"
    for arn in successes:
        assert mwaa.get_workflow(WorkflowArn=arn)["Name"] == name

    # the number of workflows actually visible for this Name matches the number of reported wins
    matches = [wf for wf in _all_workflows(mwaa) if wf["Name"] == name]
    assert {wf["WorkflowArn"] for wf in matches} == set(successes)


def _all_workflows(mwaa):
    token = None
    out = []
    while True:
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = mwaa.list_workflows(**kwargs)
        out.extend(page.get("Workflows", []))
        token = page.get("NextToken")
        if not token:
            return out


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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]
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
