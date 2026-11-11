"""blueprint-lifecycle-create-start-run-delete."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "blueprint-lifecycle-create-start-run-delete"
GROUP = "state-machine"
SERVICES = ["glue"]

_LAYOUT_PY = """
from awsglue.blueprint.workflow import Workflow, Entities
from awsglue.blueprint.job import Job


def generate_layout(user_params, system_params):
    etl_job = Job(
        Name="{}_job".format(user_params["WorkflowName"]),
        Command={
            "Name": "glueetl",
            "ScriptLocation": user_params["ScriptLocation"],
            "PythonVersion": "3",
        },
        Role=user_params["PassRole"],
    )
    return Workflow(Name=user_params["WorkflowName"], Entities=Entities(Jobs=[etl_job]))
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateBlueprint from an S3-hosted package reaches ACTIVE, StartBlueprintRun creates the
    layout's Job and SUCCEEDS, and after DeleteBlueprint both GetBlueprint and StartBlueprintRun
    fail not-found."""
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    role_arn = _create_glue_role(ctx)

    bucket = ctx.unique_name("sim2real-glue-blueprint-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)

    zip_bytes = _build_blueprint_zip()
    zip_key = "blueprints/behavioral-check.zip"
    s3.put_object(Bucket=bucket, Key=zip_key, Body=zip_bytes)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=zip_key))
    blueprint_location = f"s3://{bucket}/{zip_key}"

    blueprint_name = ctx.unique_name("sim2real-blueprint-")
    glue.create_blueprint(
        Name=blueprint_name,
        BlueprintLocation=blueprint_location,
        Tags={"sim2real": CHECK},
    )

    ctx.on_cleanup(lambda: _quiet(lambda: glue.delete_blueprint(Name=blueprint_name)))

    status = _poll_until(
        lambda: glue.get_blueprint(Name=blueprint_name)["Blueprint"]["Status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=180,
        interval_s=5,
    )
    assert status == "ACTIVE", f"blueprint registration reached {status} instead of ACTIVE"

    wf = ctx.unique_name("sim2real-wf-").replace("-", "_")
    # DeleteWorkflow leaves the layout's Job behind, so delete it explicitly.
    ctx.on_cleanup(lambda: _quiet(lambda: glue.delete_job(JobName=f"{wf}_job")))
    run_id = glue.start_blueprint_run(
        BlueprintName=blueprint_name,
        Parameters=json.dumps(
            {
                "WorkflowName": wf,
                "PassRole": role_arn,
                "ScriptLocation": f"s3://{bucket}/scripts/placeholder.py",
            }
        ),
        RoleArn=role_arn,
    )["RunId"]

    final_run = _poll_until(
        lambda: glue.get_blueprint_run(BlueprintName=blueprint_name, RunId=run_id)["BlueprintRun"],
        lambda r: r["State"] in ("SUCCEEDED", "FAILED", "ROLLING_BACK"),
        timeout_s=300,
        interval_s=10,
    )
    workflow_name = final_run.get("WorkflowName")
    if workflow_name:
        ctx.on_cleanup(lambda: _quiet(lambda: glue.delete_workflow(Name=workflow_name)))
    assert final_run["State"] == "SUCCEEDED", (
        f"blueprint run reached {final_run['State']!r} instead of SUCCEEDED: "
        f"{final_run.get('ErrorMessage')!r}"
    )

    glue.delete_blueprint(Name=blueprint_name)
    code, message = _error(lambda: glue.get_blueprint(Name=blueprint_name))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code!r}"
    expected_message = "Blueprint with given name not found."
    assert message == expected_message, (
        f"expected GetBlueprint's not-found message {expected_message!r}, got {message!r}"
    )

    run_after_delete_code, run_after_delete_message = _error(
        lambda: glue.start_blueprint_run(
            BlueprintName=blueprint_name,
            Parameters=json.dumps(
                {"WorkflowName": "unused", "PassRole": role_arn, "ScriptLocation": "s3://unused/unused.py"}
            ),
            RoleArn=role_arn,
        )
    )
    assert run_after_delete_code == "EntityNotFoundException", (
        f"expected StartBlueprintRun on a deleted blueprint to fail with EntityNotFoundException, "
        f"got {run_after_delete_code!r}"
    )
    expected_run_message = "Blueprint with given name not found."
    assert run_after_delete_message == expected_run_message, (
        f"expected StartBlueprintRun's not-found message {expected_run_message!r}, "
        f"got {run_after_delete_message!r}"
    )


def _build_blueprint_zip() -> bytes:
    cfg = json.dumps(
        {
            "layoutGenerator": "layout.generate_layout",
            "parameterSpec": {
                "WorkflowName": {"type": "String", "collection": False},
                "PassRole": {"type": "String", "collection": False},
                "ScriptLocation": {"type": "String", "collection": False},
            },
        }
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("blueprint.cfg", cfg)
        zf.writestr("layout.py", _LAYOUT_PY)
    return buf.getvalue()


def _error(fn) -> tuple[str, str]:
    """Call fn(); return the AWS error (Code, Message) it raised. An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _quiet(fn) -> None:
    """Teardown call that tolerates the resource already being gone."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition never met, last value: {value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _create_bucket(ctx, s3, bucket):
    region = ctx.region
    # us-east-1 is the one region S3 rejects an explicit LocationConstraint for;
    # this always follows ctx.region and never pins the check to a region.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _create_glue_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    # The blueprint's layout hands this same role back to Glue as the created Job's
    # Role, so the run materializes CreateJob(..., Role=role_arn) while impersonating
    # this role — it needs iam:PassRole on itself or that CreateJob call is denied and
    # the run never reaches SUCCEEDED.
    pass_role_policy_name = "sim2real-self-pass-role"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=pass_role_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": arn}],
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

    deadline = time.monotonic() + 30
    while iam.get_role(RoleName=role_name)["Role"]["Arn"] != arn and time.monotonic() < deadline:
        time.sleep(2)
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
