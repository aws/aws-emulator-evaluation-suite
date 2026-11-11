"""get-blueprint-runs-ordering-most-recent-first."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-blueprint-runs-ordering-most-recent-first"
GROUP = "ordering"
SERVICES = ["glue"]

_WORKFLOW_PREFIX = "sim2real-bp-wf-"


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetBlueprintRuns returns multiple runs of the same blueprint ordered with the most
    recently started run first, regardless of the order in which they finish."""
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    zip_key = "blueprints/blueprint.zip"
    s3.put_object(Bucket=bucket, Key=zip_key, Body=_build_blueprint_zip())
    role = _create_glue_role(ctx)

    blueprint_name = ctx.unique_name("sim2real-glue-bp-")
    glue.create_blueprint(
        Name=blueprint_name,
        BlueprintLocation=f"s3://{bucket}/{zip_key}",
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_blueprint(Name=blueprint_name))

    status = _poll_until(
        lambda: glue.get_blueprint(Name=blueprint_name)["Blueprint"]["Status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=180,
        interval_s=10,
    )
    assert status == "ACTIVE", f"blueprint failed to register: {status}"

    def _start():
        return glue.start_blueprint_run(BlueprintName=blueprint_name, RoleArn=role["arn"])["RunId"]

    run_id_1 = _retry_on_access_denied(_start, timeout_s=150, interval_s=10)
    ctx.on_cleanup(lambda: _cleanup_run_workflow(ctx, blueprint_name, run_id_1))

    # A blind sleep can't guarantee separation; wait for the actual condition the ordering
    # assertion depends on — the wall clock genuinely passing run 1's own reported StartedOn —
    # so the two runs get distinguishable timestamps instead of assuming a fixed gap suffices.
    started_on_1 = _poll_until(
        lambda: glue.get_blueprint_run(BlueprintName=blueprint_name, RunId=run_id_1)["BlueprintRun"].get(
            "StartedOn"
        ),
        lambda v: v is not None,
        timeout_s=30,
        interval_s=2,
    )
    _wait_for_clock_past(started_on_1, timeout_s=30, interval_s=1)

    run_id_2 = _start()
    ctx.on_cleanup(lambda: _cleanup_run_workflow(ctx, blueprint_name, run_id_2))
    assert run_id_2 != run_id_1

    runs = _poll_until(
        lambda: glue.get_blueprint_runs(BlueprintName=blueprint_name)["BlueprintRuns"],
        lambda rs: len({r["RunId"] for r in rs} & {run_id_1, run_id_2}) == 2,
        timeout_s=60,
        interval_s=5,
    )
    run_ids_in_order = [r["RunId"] for r in runs]
    assert run_ids_in_order[:2] == [run_id_2, run_id_1], (
        f"expected most-recent-first order [{run_id_2}, {run_id_1}], got {run_ids_in_order}"
    )
    assert runs[0]["StartedOn"] >= runs[1]["StartedOn"]


# ===== helpers =====


def _build_blueprint_zip() -> bytes:
    layout_py = (
        "import time\n"
        "from awsglue.blueprint.workflow import Workflow, Entities\n\n\n"
        "def generate_layout(user_params, system_params):\n"
        "    name = '" + _WORKFLOW_PREFIX + "{}'.format(int(time.time() * 1000000))\n"
        "    return Workflow(Name=name, Entities=Entities())\n"
    )
    cfg = json.dumps({"layoutGenerator": "layout.generate_layout", "parameterSpec": {}})
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("layout.py", layout_py)
        zf.writestr("blueprint.cfg", cfg)
    return buf.getvalue()


def _wait_for_clock_past(moment, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    while datetime.now(timezone.utc) <= moment:
        if time.monotonic() >= deadline:
            raise TimeoutError(f"clock did not advance past {moment} within {timeout_s}s")
        time.sleep(interval_s)


def _cleanup_run_workflow(ctx, blueprint_name, run_id):
    """Delete only the workflow this specific run created. Never sweep every workflow that
    shares the naming prefix — that would delete a concurrent run's workflow too."""
    glue = ctx.client("glue")
    deadline = time.monotonic() + 45.0
    workflow_name = None
    while time.monotonic() < deadline:
        try:
            br = glue.get_blueprint_run(BlueprintName=blueprint_name, RunId=run_id)["BlueprintRun"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFoundException":
                raise
            return
        workflow_name = br.get("WorkflowName")
        if br.get("State") not in ("RUNNING", "ROLLING_BACK"):
            break
        time.sleep(3)
    if workflow_name:
        try:
            glue.delete_workflow(Name=workflow_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFoundException":
                raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise TimeoutError(f"condition not met within {timeout_s}s (last={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


def _retry_on_access_denied(fn, *, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code != "AccessDeniedException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-glue-").lower().replace("_", "-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _empty_and_delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _create_glue_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    iam.attach_role_policy(
        RoleName=name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    )
    return {"name": name, "arn": role_arn}


def _delete_role(ctx, name):
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
