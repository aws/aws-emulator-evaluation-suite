"""blueprint-lifecycle-create-run-delete."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "blueprint-lifecycle-create-run-delete"
GROUP = "state-machine"
SERVICES = ["glue"]


def _error(fn) -> tuple[str, str]:
    """Call fn(); return the AWS error (Code, Message) it raised. An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _quiet(fn) -> None:
    """Teardown call that tolerates the resource already being gone."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s; last value={last!r}")


def _create_glue_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-bp-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    # The blueprint run's layout passes this same role back to Glue (as PassRole/RoleArn for
    # the Job it creates), so the role itself needs iam:PassRole on itself.
    pass_role_policy_name = "sim2real-self-pass-role"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=pass_role_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": role_arn}],
            }
        ),
    )

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=pass_role_policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _retry_call(fn, *, timeout_s: float, interval_s: float, retry_codes: tuple[str, ...]):
    """Retry fn() while it fails with one of retry_codes, bounded by timeout_s.

    IAM role trust/attach propagation to Glue is asynchronous and carries no readable
    signal to poll on the IAM side, so the wait belongs on the first call that actually
    depends on the role having propagated, not on a blind pre-sleep after CreateRole.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in retry_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


# Minimal blueprint layout: a single Job entity, no Crawler/Trigger, so registering and
# running the blueprint only creates catalog metadata (a Job definition) rather than any
# billed compute. Structure per
# https://docs.aws.amazon.com/glue/latest/dg/developing-blueprints-sample.html
_LAYOUT_PY = """
from awsglue.blueprint.workflow import *
from awsglue.blueprint.job import *


def generate_layout(user_params, system_params):
    workflow_name = user_params['WorkflowName']
    job = Job(
        Name="{}_job".format(workflow_name),
        Command={
            "Name": "pythonshell",
            "ScriptLocation": user_params['ScriptLocation'],
            "PythonVersion": "3.9",
        },
        Role=user_params['PassRole'],
    )
    return Workflow(Name=workflow_name, Entities=Entities(Jobs=[job]))
""".strip()

_BLUEPRINT_CFG = {
    "layoutGenerator": "layout.generate_layout",
    "parameterSpec": {
        "WorkflowName": {"type": "String", "collection": False, "description": "workflow name"},
        "PassRole": {"type": "String", "collection": False, "description": "role arn to pass"},
        "ScriptLocation": {"type": "S3Uri", "collection": False, "description": "job script s3 uri"},
    },
}


def _build_blueprint_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w") as zf:
        zf.writestr("layout.py", _LAYOUT_PY)
        zf.writestr("blueprint.cfg", json.dumps(_BLUEPRINT_CFG))
    return buf.getvalue()


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Blueprint transitions CREATING -> ACTIVE, a run transitions RUNNING -> SUCCEEDED (creating
    the Job entity the layout declares), then the Blueprint is deletable."""
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    role_arn = _create_glue_role(ctx)

    bucket = ctx.unique_name("sim2real-glue-bp-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _empty_and_delete_bucket():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_delete_bucket)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    key = "blueprint.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_build_blueprint_zip())
    blueprint_location = f"s3://{bucket}/{key}"

    blueprint_name = ctx.unique_name("sim2real-blueprint-")
    workflow_name = ctx.unique_name("sim2real-bp-workflow-")
    job_name = f"{workflow_name}_job"

    glue.create_blueprint(
        Name=blueprint_name, BlueprintLocation=blueprint_location, Tags={"sim2real": CHECK}
    )

    ctx.on_cleanup(lambda: _quiet(lambda: glue.delete_blueprint(Name=blueprint_name)))

    def _cleanup_run_artifacts():
        _quiet(lambda: glue.delete_job(JobName=job_name))
        _quiet(lambda: glue.delete_workflow(Name=workflow_name))

    ctx.on_cleanup(_cleanup_run_artifacts)

    def _probe_blueprint() -> dict[str, Any]:
        return glue.get_blueprint(Name=blueprint_name)["Blueprint"]

    blueprint = _poll_until(
        _probe_blueprint,
        lambda bp: bp["Status"] in ("ACTIVE", "FAILED"),
        timeout_s=180,
        interval_s=5,
    )
    assert blueprint["Status"] == "ACTIVE", f"blueprint failed: {blueprint.get('ErrorMessage')}"

    run_id = _retry_call(
        lambda: glue.start_blueprint_run(
            BlueprintName=blueprint_name,
            RoleArn=role_arn,
            Parameters=json.dumps(
                {
                    "WorkflowName": workflow_name,
                    "PassRole": role_arn,
                    "ScriptLocation": f"s3://{bucket}/does-not-need-to-exist.py",
                }
            ),
        )["RunId"],
        timeout_s=60,
        interval_s=5,
        retry_codes=("AccessDeniedException", "InvalidInputException"),
    )

    def _probe_run() -> dict[str, Any]:
        return glue.get_blueprint_run(BlueprintName=blueprint_name, RunId=run_id)["BlueprintRun"]

    bp_run = _poll_until(
        _probe_run,
        lambda r: r["State"] in ("SUCCEEDED", "FAILED", "ROLLING_BACK"),
        timeout_s=180,
        interval_s=5,
    )
    assert bp_run["State"] == "SUCCEEDED", f"state={bp_run.get('State')!r} err={bp_run.get('ErrorMessage')!r}"

    # The run's layout script declared a Job entity: assert it was actually materialized.
    # Look up the actual job name(s) from the created Workflow's graph rather than assuming
    # Glue preserved our "{workflow_name}_job" naming verbatim.
    workflow = glue.get_workflow(Name=workflow_name, IncludeGraph=True)["Workflow"]
    job_names = [n["Name"] for n in workflow.get("Graph", {}).get("Nodes", []) if n.get("Type") == "JOB"]
    assert job_names, f"blueprint run did not materialize any Job node in workflow {workflow_name!r}"
    job_name = job_names[0]
    job = glue.get_job(JobName=job_name)["Job"]
    assert job["Role"] == role_arn

    glue.delete_job(JobName=job_name)
    glue.delete_workflow(Name=workflow_name)
    glue.delete_blueprint(Name=blueprint_name)

    code, message = _error(lambda: glue.get_blueprint(Name=blueprint_name))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code!r}"
    expected_message = "Blueprint with given name not found."
    assert message == expected_message, (
        f"expected GetBlueprint's not-found message {expected_message!r}, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
