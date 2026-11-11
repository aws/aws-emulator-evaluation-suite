"""deploy-greengrassv2-deployment-nonexistent-target-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-greengrassv2-deployment-nonexistent-target-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "greengrassv2", "iot"]

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
    "Invalid Input: Target not found (Service: GreengrassV2, Status Code: 400, Request ID: <id>) "
    "(SDK Attempt Count: <n>)",
    "InvalidRequest",
)


def _template(tag_value: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"TargetArn": {"Type": "String"}},
        "Resources": {
            "Dep": {
                "Type": "AWS::GreengrassV2::Deployment",
                "Properties": {
                    "TargetArn": {"Ref": "TargetArn"},
                    "Tags": {"sim2real-check": tag_value},
                },
            },
        },
        "Outputs": {"DeploymentId": {"Value": {"Ref": "Dep"}}},
    })


def _deployments(gg, target_arn: str) -> list[dict]:
    out: list[dict] = []
    kwargs = {"targetArn": target_arn, "historyFilter": "ALL"}
    while True:
        page = gg.list_deployments(**kwargs)
        out.extend(page["deployments"])
        if not page.get("nextToken"):
            return out
        kwargs["nextToken"] = page["nextToken"]


def _user_tags(tags_map: dict) -> dict:
    """The tags minus the aws:-reserved ones the stack may add."""
    return {k: v for k, v in (tags_map or {}).items() if not k.startswith("aws:")}


def _delete_thing_ignore_missing(iot, name: str) -> None:
    try:
        iot.delete_thing(thingName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::GreengrassV2::Deployment targeting a thing ARN GreengrassV2 never
    created is rejected with GreengrassV2's own exact error and rolls back, creating no
    deployment; the identical template against a real thing still deploys.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-greengrassv2-deployment.html
    """
    gg = ctx.client("greengrassv2")
    iot = ctx.client("iot")
    cfn = ctx.client("cloudformation")

    # The real thing is the control's target; its ARN gives the bogus one its partition.
    real_thing = ctx.unique_name("sim2real-ggv2-real-thing-")
    ctx.on_cleanup(lambda: _delete_thing_ignore_missing(iot, real_thing))
    real_target = iot.create_thing(thingName=real_thing)["thingArn"]
    partition = real_target.split(":", 2)[1]

    bogus_thing = ctx.unique_name("sim2real-ggv2-missing-thing-")
    bogus_target = f"arn:{partition}:iot:{ctx.region}:{ctx.account}:thing/{bogus_thing}"

    bad_stack = ctx.unique_name("sim2real-ggv2depbad-")
    bad_id = create_stack(
        ctx, cfn, bad_stack, _template(CHECK),
        Parameters=[{"ParameterKey": "TargetArn", "ParameterValue": bogus_target}],
    )
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack {bad_stack!r} ended {status!r}, expected ROLLBACK_COMPLETE"
    )

    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Dep"), ctx.account,
                         bogus_thing)
    assert got == _REJECTED, f"expected the Dep failure reason {_REJECTED!r}, got {got!r}"

    # Effect absent: no deployment was ever created against the bogus target.
    deployments = _deployments(gg, bogus_target)
    assert deployments == [], f"expected no deployments for the bogus target, got {deployments!r}"

    resources = cfn.describe_stack_resources(StackName=bad_id)["StackResources"]
    dep_resources = [r for r in resources if r["LogicalResourceId"] == "Dep"]
    assert len(dep_resources) == 1, f"expected exactly one Dep resource row, got {dep_resources!r}"
    assert "PhysicalResourceId" not in dep_resources[0], (
        f"a CREATE_FAILED Deployment should carry no PhysicalResourceId, got "
        f"{dep_resources[0].get('PhysicalResourceId')!r}"
    )

    delete_stack(cfn, bad_id)

    # Positive control: the identical template and resource type, pointed at a real thing,
    # still deploys.
    good_stack = ctx.unique_name("sim2real-ggv2depgood-")
    good_id = create_stack(
        ctx, cfn, good_stack, _template(CHECK),
        Parameters=[{"ParameterKey": "TargetArn", "ParameterValue": real_target}],
    )
    good_status = wait_stack(cfn, good_id)
    assert good_status == "CREATE_COMPLETE", (
        f"the control stack {good_stack!r} ended {good_status!r}, expected CREATE_COMPLETE: "
        f"{decisive_rows(stack_events(cfn, good_id))!r}"
    )
    good_deployment_id = stack_outputs(cfn, good_id)["DeploymentId"]
    control = gg.get_deployment(deploymentId=good_deployment_id)
    assert control["targetArn"] == real_target, (
        f"expected the control deployment targetArn {real_target!r}, GreengrassV2 reports "
        f"{control['targetArn']!r}"
    )
    # The template's tag plus the propagated stack tag.
    want_tags = {"sim2real-check": CHECK, "sim2real": good_stack}
    assert _user_tags(control.get("tags")) == want_tags, (
        f"expected the control deployment tags {want_tags!r}, GreengrassV2 reports "
        f"{control.get('tags')!r}"
    )
    assert control["deploymentStatus"] == "ACTIVE", (
        f"expected the control deployment ACTIVE, GreengrassV2 reports "
        f"{control['deploymentStatus']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
