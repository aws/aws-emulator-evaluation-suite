"""start-blueprint-run-while-running-accepted."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "start-blueprint-run-while-running-accepted"
GROUP = "concurrency"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A second StartBlueprintRun while the first run is RUNNING is accepted with a distinct RunId;
    both runs succeed and each creates its own workflow. IllegalBlueprintStateException guards the
    blueprint's own status, not concurrent runs of an ACTIVE blueprint.
    """
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-glue-bp-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    role_arn, role_name = _create_blueprint_role(ctx, iam, bucket)

    script_body = b"import time\ntime.sleep(30)\n"
    s3.put_object(Bucket=bucket, Key="scripts/script.py", Body=script_body)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key="scripts/script.py"))

    zip_bytes = _build_blueprint_zip()
    s3.put_object(Bucket=bucket, Key="blueprints/blueprint.zip", Body=zip_bytes)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key="blueprints/blueprint.zip"))

    blueprint_name = ctx.unique_name("sim2real-glue-bp-")
    # Separate WorkflowNames: a reused name fails with AlreadyExistsException, a separate contract.
    workflow_name_2 = ctx.unique_name("sim2real_glue_bp_wf2_").replace("-", "_")

    glue.create_blueprint(
        Name=blueprint_name,
        BlueprintLocation=f"s3://{bucket}/blueprints/blueprint.zip",
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_blueprint(Name=blueprint_name))

    blueprint = _poll_until(
        lambda: glue.get_blueprint(Name=blueprint_name)["Blueprint"],
        lambda bp: bp["Status"] in ("ACTIVE", "FAILED"),
        timeout_s=_budget_s(ctx, 180),
        interval_s=1,
        ctx=ctx,
    )
    assert blueprint["Status"] == "ACTIVE", blueprint.get("ErrorMessage")

    def _params_for(workflow_name):
        return json.dumps(
            {
                "WorkflowName": workflow_name,
                "ScriptLocation": f"s3://{bucket}/scripts/script.py",
                "PassRole": role_arn,
            }
        )

    def _cleanup_workflow_and_job(workflow_name):
        from botocore.exceptions import ClientError

        for delete in (
            lambda: glue.delete_workflow(Name=workflow_name),
            lambda: glue.delete_job(JobName=f"{workflow_name}_job"),
        ):
            try:
                delete()
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "EntityNotFoundException":
                    raise

    # A blueprint run can leave RUNNING between two 1 s reads on a fast target; a run seen only in
    # a terminal state missed the window, so a fresh run (own workflow) is started, up to
    # _ATTEMPTS, until one is seen RUNNING.
    for attempt in range(_ATTEMPTS):
        workflow_name_1 = ctx.unique_name(f"sim2real_glue_bp_wf1_{attempt}_").replace("-", "_")
        run1_id = _retry_on_role_propagation(
            lambda: glue.start_blueprint_run(
                BlueprintName=blueprint_name, Parameters=_params_for(workflow_name_1), RoleArn=role_arn
            ),
            timeout_s=_budget_s(ctx, 90),
            interval_s=2,
            ctx=ctx,
        )["RunId"]
        ctx.on_cleanup(lambda name=workflow_name_1: _cleanup_workflow_and_job(name))

        state_at_second_call = _poll_until(
            lambda: glue.get_blueprint_run(BlueprintName=blueprint_name, RunId=run1_id)["BlueprintRun"][
                "State"
            ],
            lambda state: state in ("RUNNING", "SUCCEEDED", "FAILED", "ROLLING_BACK"),
            timeout_s=_budget_s(ctx, 120),
            interval_s=1,
            ctx=ctx,
        )
        if state_at_second_call == "RUNNING":
            break
    assert state_at_second_call == "RUNNING", (
        f"run1 expected RUNNING right before the concurrent StartBlueprintRun, got {state_at_second_call!r}"
    )

    run2_id = glue.start_blueprint_run(
        BlueprintName=blueprint_name, Parameters=_params_for(workflow_name_2), RoleArn=role_arn
    )["RunId"]
    ctx.on_cleanup(lambda: _cleanup_workflow_and_job(workflow_name_2))
    assert run2_id != run1_id, f"expected a distinct run id, got run1_id {run1_id!r} again"

    runs = {r["RunId"] for r in glue.get_blueprint_runs(BlueprintName=blueprint_name)["BlueprintRuns"]}
    assert {run1_id, run2_id} <= runs, f"expected both {run1_id!r} and {run2_id!r} in {runs!r}"

    final1 = _poll_until(
        lambda: glue.get_blueprint_run(BlueprintName=blueprint_name, RunId=run1_id)["BlueprintRun"][
            "State"
        ],
        lambda state: state in ("SUCCEEDED", "FAILED", "ROLLING_BACK"),
        timeout_s=_budget_s(ctx, 180),
        interval_s=1,
        ctx=ctx,
    )
    run1_final = glue.get_blueprint_run(BlueprintName=blueprint_name, RunId=run1_id)["BlueprintRun"]
    assert final1 == "SUCCEEDED", f"run1 expected SUCCEEDED, got {final1!r}: {run1_final.get('ErrorMessage')}"

    final2 = _poll_until(
        lambda: glue.get_blueprint_run(BlueprintName=blueprint_name, RunId=run2_id)["BlueprintRun"][
            "State"
        ],
        lambda state: state in ("SUCCEEDED", "FAILED", "ROLLING_BACK"),
        timeout_s=_budget_s(ctx, 180),
        interval_s=1,
        ctx=ctx,
    )
    run2_final = glue.get_blueprint_run(BlueprintName=blueprint_name, RunId=run2_id)["BlueprintRun"]
    assert final2 == "SUCCEEDED", f"run2 expected SUCCEEDED, got {final2!r}: {run2_final.get('ErrorMessage')}"

    names = {
        glue.get_workflow(Name=workflow_name_1)["Workflow"]["Name"],
        glue.get_workflow(Name=workflow_name_2)["Workflow"]["Name"],
    }
    assert names == {workflow_name_1, workflow_name_2}, names


# ===== helpers =====

_ATTEMPTS = 3


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() + interval_s >= deadline:
            break
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("blueprint wait condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _retry_on_role_propagation(fn, timeout_s=90.0, interval_s=5.0, ctx=None):
    """Call fn(); if it raises AccessDeniedException (IAM role trust propagation lag), retry
    until timeout_s. Returns fn()'s result on success, re-raises the terminal error otherwise."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            if e.response["Error"]["Code"] == "AccessDeniedException" and ctx is not None and _budget_spent(ctx):
                raise TimeoutError("StartBlueprintRun past role propagation: the run budget ended first; not graded") from e
            raise


def _build_blueprint_zip() -> bytes:
    cfg = {
        "layoutGenerator": "layout.generate_layout",
        "parameterSpec": {
            "WorkflowName": {"type": "String", "collection": False},
            "ScriptLocation": {"type": "String", "collection": False},
            "PassRole": {"type": "String", "collection": False},
        },
    }
    layout_py = (
        "from awsglue.blueprint.workflow import *\n"
        "from awsglue.blueprint.job import *\n"
        "\n"
        "\n"
        "def generate_layout(user_params, system_params):\n"
        "    job = Job(\n"
        "        Name=user_params['WorkflowName'] + '_job',\n"
        "        Command={\n"
        "            'Name': 'pythonshell',\n"
        "            'ScriptLocation': user_params['ScriptLocation'],\n"
        "            'PythonVersion': '3.9',\n"
        "        },\n"
        "        Role=user_params['PassRole'],\n"
        "    )\n"
        "    return Workflow(Name=user_params['WorkflowName'], Entities=Entities(Jobs=[job]))\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("blueprint.cfg", json.dumps(cfg))
        zf.writestr("layout.py", layout_py)
    return buf.getvalue()


def _create_blueprint_role(ctx, iam, bucket):
    role_name = ctx.unique_name("sim2real-glue-bprole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
        )
    )
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(inline_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"))

    # The blueprint run's layout passes this same role back to Glue (as PassRole/RoleArn for
    # the Job it creates), so the role itself needs iam:PassRole on itself.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="self-pass-role",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": role["Arn"]}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="self-pass-role"))
    return role["Arn"], role_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
