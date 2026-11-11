"""deploy-ssm-opsitem-via-cloudformation-then-lifecycle."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ssm-opsitem-via-cloudformation-then-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "ssm"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


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


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


# ---- Check-specific: the template, then run(). ----

_DESCRIPTION = "sim2real deploy-then-lifecycle test item"


def _template(title, source):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Item": {
                "Type": "AWS::SSM::OpsItem",
                "Properties": {"Title": title, "Description": _DESCRIPTION, "Source": source},
            }
        },
        "Outputs": {"ItemArn": {"Value": {"Ref": "Item"}}},
    })


def _own_tags(ssm, resource_type, resource_id):
    rows = ssm.list_tags_for_resource(ResourceType=resource_type, ResourceId=resource_id)
    return {t["Key"]: t["Value"] for t in rows["TagList"] if not t["Key"].startswith("aws:")}


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation SSM OpsItem reads back its Title, Description, Source and tag through SSM.

    Ref is the documented OpsItem ARN of the item DescribeOpsItems lists, and the stack delete
    removes it.
    """
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    stack = ctx.unique_name("sim2real-ssmopsitem-stack-")
    title = ctx.unique_name("sim2real-ssmopsitem-")
    source = ctx.unique_name("sim2real-src-")

    stack_id = create_stack(ctx, cfn, stack, _template(title, source))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    item_arn = stack_outputs(cfn, stack_id)["ItemArn"]
    partition = stack_id.split(":")[1]

    # Ref against an independent read: DescribeOpsItems filtered to this run's own title.
    listed = paginate(ssm, "describe_ops_items", "OpsItemSummaries",
                      OpsItemFilters=[{"Key": "Title", "Values": [title], "Operator": "Equal"}])
    assert len(listed) == 1, f"DescribeOpsItems for {title!r} found {listed!r}"
    item_id = listed[0]["OpsItemId"]
    want_arn = f"arn:{partition}:ssm:{ctx.region}:{ctx.account}:opsitem/{item_id}"
    assert item_arn == want_arn, f"Ref {item_arn!r} != the documented OpsItem ARN {want_arn!r}"

    got = ssm.get_ops_item(OpsItemId=item_id)["OpsItem"]
    got = {k: got[k] for k in ("OpsItemArn", "Title", "Description", "Source", "Status")}
    want = {"OpsItemArn": item_arn, "Title": title, "Description": _DESCRIPTION,
            "Source": source, "Status": "Open"}
    assert got == want, f"GetOpsItem reads {got!r}, expected {want!r}"
    item_tags = _own_tags(ssm, "OpsItem", item_id)
    assert item_tags == {"sim2real": stack}, f"OpsItem tags {item_tags!r}"

    delete_stack(cfn, stack_id)
    try:
        ssm.get_ops_item(OpsItemId=item_id)
    except ClientError as exc:
        error = exc.response["Error"]
        got = (error.get("Code"), masked(error.get("Message", ""), ctx.account))
    else:
        raise AssertionError(f"OpsItem {item_id} still answers after the stack delete")
    want = ("OpsItemNotFoundException",
            "OpsItem not found. (Service: AmazonSSM; Status Code: 400; Error Code: "
            "OpsItemNotFoundException; Request ID: <id>; Proxy: null)")
    assert got == want, f"GetOpsItem after the delete {got!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
