"""deploy-gamelift-script-missing-nodejs-version-rejected-and-rolled-back."""
from __future__ import annotations

import io
import json
import re
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-gamelift-script-missing-nodejs-version-rejected-and-rolled-back"
GROUP = "cloudformation"
SERVICES = ["cloudformation", "gamelift", "iam", "s3"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


# ---- Check-specific: the template, then run(). ----

_REJECTED = (
    "The NodeJsVersion parameter is required. See the GameLift API Reference for CreateScript() "
    "for a list of supported runtime versions. (Service: GameLift, Status Code: 400, "
    "Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)
_KEY = "script.zip"
_SCRIPT_JS = "exports.ssExports = { onProcessStarted: function () {} };"


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("main.js", _SCRIPT_JS)
    return buf.getvalue()


def _template(bucket: str, role_arn: str, script_name: str, *, node_js_version: str | None) -> str:
    props = {
        "Name": script_name,
        "StorageLocation": {"Bucket": bucket, "Key": _KEY, "RoleArn": role_arn},
    }
    if node_js_version is not None:
        props["NodeJsVersion"] = node_js_version
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Script": {"Type": "AWS::GameLift::Script", "Properties": props}},
        "Outputs": {"ScriptId": {"Value": {"Ref": "Script"}}},
    })


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _scripts_named(gl, name: str) -> list[str]:
    """The ScriptId of every script called ``name``, read across all pages of ListScripts."""
    ids: list[str] = []
    kwargs: dict = {}
    while True:
        page = gl.list_scripts(**kwargs)
        ids += [sc["ScriptId"] for sc in page.get("Scripts", []) if sc.get("Name") == name]
        if not page.get("NextToken"):
            return ids
        kwargs["NextToken"] = page["NextToken"]


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """Empty and delete the bucket; only its own NoSuchBucket means it was never created."""
    try:
        for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::GameLift::Script with a StorageLocation but no NodeJsVersion is
    rejected with GameLift's reason and rolls back leaving no script in GameLift; the same
    template with NodeJsVersion set succeeds and reads back.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-gamelift-script.html
    """
    s3 = ctx.client("s3")
    gl = ctx.client("gamelift")
    iam = ctx.client("iam")
    cfn = ctx.client("cloudformation")

    bucket = ctx.unique_name("sim2real-glscriptbad-bkt-")
    bucket_kw = ({} if ctx.region == "us-east-1"
                 else {"CreateBucketConfiguration": {"LocationConstraint": ctx.region}})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.create_bucket(Bucket=bucket, **bucket_kw)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})
    s3.put_object(Bucket=bucket, Key=_KEY, Body=_zip_bytes())

    role_name = ctx.unique_name("sim2real-glscriptbad-role-")
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(
        RoleName=role_name, PolicyName="ScriptAccess"), "NoSuchEntity"))
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                            "Principal": {"Service": "gamelift.amazonaws.com"}}],
        }),
        Tags=[{"Key": "sim2real", "Value": role_name}],
    )["Role"]
    iam.put_role_policy(
        RoleName=role_name, PolicyName="ScriptAccess",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion"],
                            "Resource": f"arn:{role['Arn'].split(':')[1]}:s3:::{bucket}/{_KEY}"}],
        }),
    )

    bad_stack = ctx.unique_name("sim2real-glscriptbad-")
    bad_name = ctx.unique_name("sim2real-glscriptbad-name-")
    bad_id = create_stack(ctx, cfn, bad_stack,
                          _template(bucket, role["Arn"], bad_name, node_js_version=None))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"stack {bad_stack!r} ended {status!r}, expected ROLLBACK_COMPLETE"

    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Script"), ctx.account,
                         bad_name)
    assert got == _REJECTED, f"Script CREATE_FAILED reason: expected {_REJECTED!r}, got {got!r}"

    # Positive control: the identical mechanism, with NodeJsVersion set, still succeeds.
    good_stack = ctx.unique_name("sim2real-glscriptgood-")
    good_name = ctx.unique_name("sim2real-glscriptgood-name-")
    good_id = create_stack(ctx, cfn, good_stack,
                           _template(bucket, role["Arn"], good_name, node_js_version="24.x"))
    good_status = wait_stack(cfn, good_id)
    assert good_status == "CREATE_COMPLETE", (
        f"the control stack {good_stack!r} ended {good_status!r}, expected CREATE_COMPLETE: "
        f"{decisive_rows(stack_events(cfn, good_id))!r}"
    )
    good_script_id = stack_outputs(cfn, good_id)["ScriptId"]
    control = gl.describe_script(ScriptId=good_script_id)["Script"]
    assert control["ScriptId"] == good_script_id, (
        f"expected the control ScriptId {good_script_id!r}, GameLift reports {control['ScriptId']!r}"
    )
    assert control["Name"] == good_name, (
        f"expected the control script Name {good_name!r}, GameLift reports {control['Name']!r}"
    )
    assert control["NodeJsVersion"] == "24.x", (
        f"expected the control NodeJsVersion '24.x', GameLift reports {control.get('NodeJsVersion')!r}"
    )

    # Before any stack is deleted: GameLift holds the control script and no script under the
    # rejected name, so the rollback left nothing behind.
    held = _scripts_named(gl, good_name)
    assert held == [good_script_id], (
        f"expected ListScripts to hold the control {good_name!r} once, got {held!r}"
    )
    leftover = _scripts_named(gl, bad_name)
    assert leftover == [], f"expected no script named {bad_name!r} after the rollback, got {leftover!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
