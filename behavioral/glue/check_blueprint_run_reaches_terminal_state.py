"""blueprint-run-reaches-terminal-state."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "blueprint-run-reaches-terminal-state"
GROUP = "server-side"
SERVICES = ["glue"]

# A blueprint run creates a Glue Workflow from the layout script and runs it to a terminal state with no
# further client action. A workflow with zero entities finishes in well under a minute and always ends FAILED
# with ErrorMessage "Actions cannot be null or empty": Glue rejects an empty workflow graph as unrunnable.
_TERMINAL_STATES = {"SUCCEEDED", "FAILED", "ROLLED_BACK"}
_EXPECTED_FAILED_ERROR_SUBSTRING = "Actions cannot be null or empty"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A blueprint whose layout yields a workflow with no actions activates, and its StartBlueprintRun reaches
    FAILED with an ErrorMessage containing 'Actions cannot be null or empty'.
    """
    glue = ctx.client("glue")
    bucket = _create_bucket(ctx)
    role_arn = _create_glue_service_role(ctx, s3_bucket=bucket)

    blueprint_name = ctx.unique_name("sim2real-glue-bp-")
    workflow_name = ctx.unique_name("sim2real-glue-bpwf-")
    zip_key = "blueprint.zip"
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key=zip_key, Body=_build_empty_workflow_blueprint_zip())
    location = f"s3://{bucket}/{zip_key}"

    glue.create_blueprint(Name=blueprint_name, BlueprintLocation=location, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_blueprint(Name=blueprint_name))

    blueprint = _poll_until(
        lambda: glue.get_blueprint(Name=blueprint_name)["Blueprint"],
        lambda b: b["Status"] in ("ACTIVE", "FAILED"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert blueprint["Status"] == "ACTIVE", f"blueprint failed to activate: {blueprint}"

    run_id = _retry_call(
        lambda: glue.start_blueprint_run(
            BlueprintName=blueprint_name,
            RoleArn=role_arn,
            Parameters=json.dumps({"WorkflowName": workflow_name}),
        )["RunId"],
        timeout_s=90.0,
        interval_s=5.0,
    )

    workflow_name_seen = {"value": None}

    def _probe():
        br = glue.get_blueprint_run(BlueprintName=blueprint_name, RunId=run_id)["BlueprintRun"]
        if br.get("WorkflowName"):
            workflow_name_seen["value"] = br["WorkflowName"]
        return br

    final_run = _poll_until(
        _probe,
        lambda br: br["State"] not in ("RUNNING", "ROLLING_BACK"),
        timeout_s=240.0,
        interval_s=5.0,
    )

    if workflow_name_seen["value"]:
        wf_name = workflow_name_seen["value"]
        ctx.on_cleanup(lambda: _delete_workflow_if_exists(glue, wf_name))

    assert final_run["State"] in _TERMINAL_STATES, f"blueprint run never reached a terminal state: {final_run}"
    assert final_run["State"] == "FAILED", (
        f"expected FAILED for a zero-entity workflow (Glue rejects an empty graph as "
        f"unrunnable), got {final_run['State']!r}: {final_run}"
    )
    error_message = final_run.get("ErrorMessage", "")
    assert _EXPECTED_FAILED_ERROR_SUBSTRING in error_message, (
        f"expected ErrorMessage to contain {_EXPECTED_FAILED_ERROR_SUBSTRING!r}, "
        f"got {error_message!r}: {final_run}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _retry_call(fn, timeout_s=60.0, interval_s=5.0, retry_codes=("AccessDeniedException", "InvalidInputException")):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in retry_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-glue-bp-").replace("_", "-").lower()
    if ctx.region == "us-east-1":
        # CreateBucket rejects an explicit LocationConstraint for us-east-1 itself; this is a
        # transport quirk of the API, not a pinned target region (ctx.region drives it above).
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_glue_service_role(ctx, s3_bucket=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-bp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    if s3_bucket:
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{s3_bucket}", f"arn:aws:s3:::{s3_bucket}/*"],
            }],
        }
        iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(policy_doc))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _build_empty_workflow_blueprint_zip() -> bytes:
    cfg = {
        "layoutGenerator": "Layout.generate_layout",
        "parameterSpec": {"WorkflowName": {"type": "String", "collection": False}},
    }
    layout_py = (
        "from awsglue.blueprint.workflow import Workflow, Entities\n\n"
        "def generate_layout(user_params, system_params):\n"
        "    return Workflow(Name=user_params['WorkflowName'], "
        "Entities=Entities(Jobs=[], Crawlers=[], Triggers=[]))\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("blueprint.cfg", json.dumps(cfg))
        zf.writestr("Layout.py", layout_py)
    return buf.getvalue()


def _delete_workflow_if_exists(glue, name):
    try:
        glue.delete_workflow(Name=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
