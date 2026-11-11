"""blueprint-run-timeout-reflected-in-status."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "blueprint-run-timeout-reflected-in-status"
GROUP = "visibility-timeout-ttl"
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


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Blueprint at a missing S3 object reaches FAILED and StartBlueprintRun on it is refused with
    IllegalBlueprintStateException, creating no run; an ACTIVE Blueprint starts a run normally.

    Reference: https://docs.aws.amazon.com/glue/latest/dg/aws-glue-api-workflow.html
    """
    # BlueprintRunState has no TIMEOUT value and StartBlueprintRun takes no time limit, so the
    # closest deterministic terminal transition (CREATING -> FAILED) is driven instead.
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    role_arn = _create_glue_service_role(ctx)

    blueprint_name = ctx.unique_name("sim2real-glue-bp-")
    # No object is ever uploaded here, so the async blueprint fetch fails.
    missing_location = f"s3://{bucket}/blueprints/{blueprint_name}.zip"

    glue.create_blueprint(Name=blueprint_name, BlueprintLocation=missing_location)
    ctx.on_cleanup(lambda: _safe_call(glue.delete_blueprint, Name=blueprint_name))

    blueprint = _poll_until(
        lambda: glue.get_blueprint(Name=blueprint_name)["Blueprint"],
        lambda bp: bp["Status"] != "CREATING",
        timeout_s=120,
        interval_s=5,
    )
    assert blueprint["Status"] == "FAILED", (
        f"expected a Blueprint registered against a nonexistent S3 object to "
        f"reach FAILED, got {blueprint['Status']}"
    )
    expected_reason = f"Access denied on object at location: {missing_location}."
    assert blueprint.get("ErrorMessage") == expected_reason, (
        f"expected the FAILED Blueprint's ErrorMessage {expected_reason!r}, got {blueprint.get('ErrorMessage')!r}"
    )

    code, message = _error(
        lambda: glue.start_blueprint_run(BlueprintName=blueprint_name, RoleArn=role_arn)
    )
    assert code == "IllegalBlueprintStateException", (
        f"expected IllegalBlueprintStateException for a non-ACTIVE blueprint, got {code}"
    )
    expected_message = f"No active definition found for Blueprint: {blueprint_name}"
    assert message == expected_message, (
        f"expected StartBlueprintRun's non-ACTIVE refusal message {expected_message!r}, got {message!r}"
    )

    runs = glue.get_blueprint_runs(BlueprintName=blueprint_name)["BlueprintRuns"]
    assert runs == [], f"expected no BlueprintRuns after a rejected StartBlueprintRun, got {runs}"

    # Positive control: the rejection above is specific to the non-ACTIVE state.
    good_key = "blueprints/good.zip"
    s3.put_object(Bucket=bucket, Key=good_key, Body=_build_blueprint_zip())
    ctx.on_cleanup(lambda: _safe_call(s3.delete_object, Bucket=bucket, Key=good_key))
    good_location = f"s3://{bucket}/{good_key}"

    good_name = ctx.unique_name("sim2real-glue-bp-good-")
    glue.create_blueprint(Name=good_name, BlueprintLocation=good_location)
    ctx.on_cleanup(lambda: _safe_call(glue.delete_blueprint, Name=good_name))

    good_status = _poll_until(
        lambda: glue.get_blueprint(Name=good_name)["Blueprint"]["Status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=120,
        interval_s=5,
    )
    assert good_status == "ACTIVE", (
        f"expected the positive-control Blueprint to register ACTIVE, got {good_status}"
    )

    workflow_name = ctx.unique_name("sim2real-glue-bpwf-")
    job_name = f"{workflow_name}_job"
    ctx.on_cleanup(lambda: _safe_call(glue.delete_workflow, Name=workflow_name))
    ctx.on_cleanup(lambda: _safe_call(glue.delete_job, JobName=job_name))

    good_run_id = glue.start_blueprint_run(
        BlueprintName=good_name,
        RoleArn=role_arn,
        Parameters=json.dumps(
            {
                "WorkflowName": workflow_name,
                "PassRole": role_arn,
                "ScriptLocation": f"s3://{bucket}/scripts/placeholder.py",
            }
        ),
    )["RunId"]
    # Runs first (LIFO): the workflow and job are deleted only after the run stops creating them.
    ctx.on_cleanup(lambda: _poll_until(
        lambda: glue.get_blueprint_run(BlueprintName=good_name, RunId=good_run_id)["BlueprintRun"]["State"],
        lambda state: state not in ("RUNNING", "ROLLING_BACK"),
        timeout_s=300,
    ))
    assert good_run_id, "expected StartBlueprintRun on an ACTIVE blueprint to return a RunId"

    good_run = glue.get_blueprint_run(BlueprintName=good_name, RunId=good_run_id)["BlueprintRun"]
    assert good_run["State"] in ("RUNNING", "SUCCEEDED", "FAILED", "ROLLING_BACK"), (
        f"expected a real BlueprintRun for the ACTIVE blueprint, got state {good_run['State']!r}"
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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _error(fn) -> tuple[str, str]:
    """Call fn(); return the AWS error (Code, Message) it raised. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_call(fn, **kwargs):
    """Delete, tolerating not-found; retry ConcurrentModificationException every 2 s for 60 s."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            fn(**kwargs)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("EntityNotFoundException", "NoSuchBucket", "NoSuchKey"):
                return
            if code != "ConcurrentModificationException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_glue_service_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "glue.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
    )
    role_arn = resp["Role"]["Arn"]
    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-glue-bp-")

    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )

    def _cleanup():
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            for obj in objs:
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
