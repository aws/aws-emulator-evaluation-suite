"""e2e-blueprint-run-deploys-workflow-flow."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "e2e-blueprint-run-deploys-workflow-flow"
GROUP = "e2e"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Starting a blueprint run and polling it to SUCCEEDED results in the
    blueprint's generated workflow and job actually existing in the catalog, with
    the job's role and script matching what the layout script specified."""
    glue = ctx.client("glue")
    bucket = _create_bucket(ctx)
    role_arn = _create_glue_role(ctx, bucket)

    workflow_name = ctx.unique_name("sim2real-bp-wf-").replace("-", "_")
    script_key = "scripts/hello.py"
    ctx.client("s3").put_object(Bucket=bucket, Key=script_key, Body=b"print('hello from sim2real blueprint')\n")
    script_location = f"s3://{bucket}/{script_key}"

    blueprint_key = "blueprint/blueprint.zip"
    _upload_blueprint_zip(ctx, bucket, blueprint_key)
    blueprint_location = f"s3://{bucket}/{blueprint_key}"

    blueprint_name = ctx.unique_name("sim2real-blueprint-")
    glue.create_blueprint(
        Name=blueprint_name,
        BlueprintLocation=blueprint_location,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_blueprint(Name=blueprint_name))

    blueprint = _poll_until(
        lambda: glue.get_blueprint(Name=blueprint_name)["Blueprint"],
        lambda b: b["Status"] in ("ACTIVE", "FAILED"),
        timeout_s=180.0,
        interval_s=10.0,
    )
    assert blueprint["Status"] == "ACTIVE", f"blueprint registration failed: {blueprint}"

    parameters = json.dumps(
        {"WorkflowName": workflow_name, "ScriptLocation": script_location, "PassRole": role_arn}
    )
    run_id = _retry_role_propagation(
        lambda: glue.start_blueprint_run(
            BlueprintName=blueprint_name, Parameters=parameters, RoleArn=role_arn
        )
    )["RunId"]

    blueprint_run = _poll_until(
        lambda: glue.get_blueprint_run(BlueprintName=blueprint_name, RunId=run_id)["BlueprintRun"],
        lambda r: r["State"] in ("SUCCEEDED", "FAILED", "ROLLED_BACK"),
        timeout_s=180.0,
        interval_s=10.0,
    )
    assert blueprint_run["State"] == "SUCCEEDED", (
        f"err={blueprint_run.get('ErrorMessage')}"
    )
    assert blueprint_run["WorkflowName"] == workflow_name

    ctx.on_cleanup(lambda: glue.delete_workflow(Name=workflow_name))
    workflow = glue.get_workflow(Name=workflow_name, IncludeGraph=True)
    assert workflow["Workflow"]["Name"] == workflow_name

    job_nodes = [
        node for node in workflow["Workflow"]["Graph"]["Nodes"] if node["Type"] == "JOB"
    ]
    assert job_nodes, f"blueprint-generated workflow has no job node: {workflow['Workflow']['Graph']}"
    job_name = job_nodes[0]["Name"]
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))
    job = glue.get_job(JobName=job_name)
    assert job["Job"]["Role"] == role_arn
    assert job["Job"]["Command"]["ScriptLocation"] == script_location


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value={last!r})")


def _retry_role_propagation(fn, *, timeout_s=90.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            last_err = err
            code = err.response["Error"]["Code"]
            if code in ("InvalidInputException", "IllegalBlueprintStateException"):
                time.sleep(interval_s)
                continue
            raise
    if last_err is not None:
        raise last_err
    raise AssertionError("retry_role_propagation exhausted without an error to raise")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-glue-bp-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _upload_blueprint_zip(ctx, bucket, key):
    s3 = ctx.client("s3")
    layout_py = (
        "from awsglue.blueprint.workflow import *\n"
        "from awsglue.blueprint.job import *\n"
        "\n"
        "def generate_layout(user_params, system_params):\n"
        "    etl_job = Job(Name=\"{}_job\".format(user_params['WorkflowName']),\n"
        "                  Command={\n"
        "                      'Name': 'pythonshell',\n"
        "                      'ScriptLocation': user_params['ScriptLocation'],\n"
        "                      'PythonVersion': '3.9'\n"
        "                  },\n"
        "                  Role=user_params['PassRole'])\n"
        "    return Workflow(Name=user_params['WorkflowName'], Entities=Entities(Jobs=[etl_job]))\n"
    )
    blueprint_cfg = json.dumps(
        {
            "layoutGenerator": "Layout.generate_layout",
            "parameterSpec": {
                "WorkflowName": {"type": "String", "collection": False, "description": "Workflow name."},
                "ScriptLocation": {"type": "S3Uri", "collection": False, "description": "ETL script location."},
                "PassRole": {"type": "IAMRoleName", "collection": False, "description": "IAM role."},
            },
        }
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Layout.py", layout_py)
        zf.writestr("blueprint.cfg", blueprint_cfg)
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())


def _create_glue_role(ctx, bucket):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-bp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    managed_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn))
    return role["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
