"""e2e-blueprint-deployment-flow."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-blueprint-deployment-flow"
GROUP = "e2e"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Create a blueprint, start a run, poll to SUCCEEDED, and assert the blueprint's
    declared workflow and job were actually provisioned as a consequence -- not just
    that StartBlueprintRun/GetBlueprintRun reported success."""
    glue = ctx.client("glue")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    role_arn = _create_glue_role(ctx)

    script_key = "scripts/blueprint_job.py"
    s3.put_object(Bucket=bucket, Key=script_key, Body=b"print('blueprint-provisioned job ran')\n")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=script_key))
    script_location = f"s3://{bucket}/{script_key}"

    blueprint_key = "blueprints/blueprint.zip"
    s3.put_object(Bucket=bucket, Key=blueprint_key, Body=_build_blueprint_zip())
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=blueprint_key))
    blueprint_location = f"s3://{bucket}/{blueprint_key}"

    blueprint_name = ctx.unique_name("sim2real-behav-bp-")
    glue.create_blueprint(
        Name=blueprint_name,
        BlueprintLocation=blueprint_location,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_blueprint(Name=blueprint_name))

    bp_status = _poll_until(
        lambda: glue.get_blueprint(Name=blueprint_name)["Blueprint"]["Status"],
        lambda s: s in {"ACTIVE", "FAILED"},
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert bp_status == "ACTIVE", f"blueprint registration failed (status={bp_status})"

    workflow_name = ctx.unique_name("sim2real-behav-bpwf-")
    params = json.dumps({"WorkflowName": workflow_name, "PassRole": role_arn, "ScriptLocation": script_location})
    run_id = glue.start_blueprint_run(BlueprintName=blueprint_name, Parameters=params, RoleArn=role_arn)["RunId"]

    provisioned_job_name = [None]

    def _cleanup_provisioned():
        try:
            if provisioned_job_name[0]:
                glue.delete_job(JobName=provisioned_job_name[0])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFoundException":
                raise
        try:
            glue.delete_workflow(Name=workflow_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_provisioned)

    blueprint_run = _poll_until(
        lambda: glue.get_blueprint_run(BlueprintName=blueprint_name, RunId=run_id)["BlueprintRun"],
        lambda r: r["State"] in {"SUCCEEDED", "FAILED", "ROLLING_BACK"},
        timeout_s=300.0,
        interval_s=10.0,
    )
    final_state = blueprint_run["State"]
    assert final_state == "SUCCEEDED", (
        f"blueprint run ended in {final_state}, error={blueprint_run.get('ErrorMessage')!r}"
    )

    # The declared workflow and job must actually exist now, not merely a SUCCEEDED status.
    # The job's name is whatever the blueprint's layout script chose, so read it from the
    # provisioned graph rather than assuming a naming convention.
    workflow = glue.get_workflow(Name=workflow_name, IncludeGraph=True)
    assert workflow["Workflow"]["Name"] == workflow_name

    job_nodes = [n for n in workflow["Workflow"]["Graph"]["Nodes"] if n["Type"] == "JOB"]
    assert job_nodes, f"blueprint-generated workflow has no job node: {workflow['Workflow']['Graph']}"
    job_name = job_nodes[0]["Name"]
    provisioned_job_name[0] = job_name

    job = glue.get_job(JobName=job_name)
    assert job["Job"]["Role"] == role_arn, f"expected job role {role_arn!r}, got {job['Job']['Role']!r}"
    assert job["Job"]["Command"]["ScriptLocation"] == script_location


# ===== helpers =====
def _build_blueprint_zip():
    layout_py = (
        "from awsglue.blueprint.workflow import *\n"
        "from awsglue.blueprint.job import *\n"
        "\n\n"
        "def generate_layout(user_params, system_params):\n"
        "    etl_job = Job(Name=\"{}_job\".format(user_params['WorkflowName']),\n"
        "                  Command={\n"
        "                      \"Name\": \"pythonshell\",\n"
        "                      \"ScriptLocation\": user_params['ScriptLocation'],\n"
        "                      \"PythonVersion\": \"3.9\",\n"
        "                  },\n"
        "                  Role=user_params['PassRole'])\n"
        "    return Workflow(Name=user_params['WorkflowName'], Entities=Entities(Jobs=[etl_job]))\n"
    )
    blueprint_cfg = json.dumps(
        {
            "layoutGenerator": "Layout.generate_layout",
            "parameterSpec": {
                "WorkflowName": {"type": "String", "collection": False},
                "PassRole": {"type": "IAMRoleName", "collection": False},
                "ScriptLocation": {"type": "S3Uri", "collection": False},
            },
        }
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Layout.py", layout_py)
        zf.writestr("blueprint.cfg", blueprint_cfg)
    return buf.getvalue()


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-bp-").lower().replace("_", "-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        # S3 CreateBucket API quirk: LocationConstraint must be omitted for us-east-1,
        # not a hardcoded operating region.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _create_glue_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-bprole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # The blueprint layout hands this same role to CreateJob as the job's execution role, and
    # that call is made by a session assumed from this role -- so it must be allowed to pass itself.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="allow-self-pass-role",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": role_arn}]}
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="allow-self-pass-role"))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
        )
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess")
    )
    return role_arn


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
