"""cfn-deploy-neptune-cluster-parameter-group-invalid-value-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-neptune-cluster-parameter-group-invalid-value-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "neptune"]

# ---- CloudFormation helpers: copy VERBATIM; delete the ones the check never calls. ----

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


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_FAMILY = "neptune1.3"
_PARAM = "neptune_streams_expiry_days"
_DESCRIPTION = "sim2real neptune cluster parameter group"


def _template(name: str, value: str, tag_value: str) -> str:
    """One cluster parameter group; the rejected and control stacks differ only in ``value``."""
    t = [{"Key": "sim2real-check", "Value": tag_value}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Cpg": {
                "Type": "AWS::Neptune::DBClusterParameterGroup",
                "Properties": {
                    "Name": name,
                    "Family": _FAMILY,
                    "Description": _DESCRIPTION,
                    "Parameters": {_PARAM: value},
                    "Tags": t,
                },
            },
        },
        "Outputs": {"Name": {"Value": {"Ref": "Cpg"}}},
    })


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Neptune::DBClusterParameterGroup whose Parameters value is outside
    the parameter's allowed range is rejected by Neptune, and the stack rolls back leaving no
    group; the identical mechanism with an in-range value still succeeds.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-neptune-dbclusterparametergroup.html
    """
    nep = ctx.client("neptune")
    cfn = ctx.client("cloudformation")

    defaults = nep.describe_engine_default_cluster_parameters(
        DBParameterGroupFamily=_FAMILY
    )["EngineDefaults"]["Parameters"]
    param = next(p for p in defaults if p["ParameterName"] == _PARAM)
    lo, hi = (int(x) for x in param["AllowedValues"].split("-"))
    bad_value = str(hi + 1)
    good_value = str(hi)

    bad_stack = ctx.unique_name("sim2real-nep-cpgbad-")
    bad_name = ctx.unique_name("sim2real-nep-cpgbadname-")
    bad_id = create_stack(ctx, cfn, bad_stack, _template(bad_name, bad_value, CHECK))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack {bad_stack!r} ended {status!r}, expected ROLLBACK_COMPLETE"
    )

    got_reason = handler_reason(failed_reason(stack_events(cfn, bad_id), "Cpg"), ctx.account)
    want_reason = (
        f"Value: {bad_value} is outside of range: {lo}-{hi} for parameter: {_PARAM} "
        f"(Service: Neptune, Status Code: 400, Request ID: <id>) "
        f"(SDK Attempt Count: <n>)",
        "InvalidRequest",
    )
    assert got_reason == want_reason, (
        f"expected the Cpg CREATE_FAILED reason to equal {want_reason!r}, got {got_reason!r}"
    )

    bad_absent = ("DBParameterGroupNotFound", f"DBClusterParameterGroup not found: {bad_name}")
    expect_error(
        lambda: nep.describe_db_cluster_parameter_groups(DBClusterParameterGroupName=bad_name),
        *bad_absent,
    )
    delete_stack(cfn, bad_id)

    # Positive control: the identical mechanism, given an in-range value, succeeds.
    good_stack = ctx.unique_name("sim2real-nep-cpggood-")
    good_name = ctx.unique_name("sim2real-nep-cpggoodname-")
    good_id = create_stack(ctx, cfn, good_stack, _template(good_name, good_value, CHECK))
    good_status = wait_stack(cfn, good_id)
    assert good_status == "CREATE_COMPLETE", (
        f"the control stack {good_stack!r} ended {good_status!r}: "
        f"{decisive_rows(stack_events(cfn, good_id))!r}"
    )
    good_ref = stack_outputs(cfn, good_id)["Name"]
    assert good_ref == good_name, f"expected Ref {good_name!r}, got {good_ref!r}"

    groups = nep.describe_db_cluster_parameter_groups(
        DBClusterParameterGroupName=good_ref
    )["DBClusterParameterGroups"]
    assert len(groups) == 1, f"expected one control group {good_ref!r}, got {len(groups)}"
    group = groups[0]
    assert (group["DBParameterGroupFamily"], group["Description"]) == (_FAMILY, _DESCRIPTION), (
        f"expected the control group's family and description {(_FAMILY, _DESCRIPTION)!r}, "
        f"Neptune reports {(group['DBParameterGroupFamily'], group['Description'])!r}"
    )
    group_tags = nep.list_tags_for_resource(
        ResourceName=group["DBClusterParameterGroupArn"]
    )["TagList"]
    found = {t["Key"]: t["Value"] for t in group_tags if not t["Key"].startswith("aws:")}
    want_tags = {"sim2real": good_stack, "sim2real-check": CHECK}
    assert found == want_tags, f"expected tags {want_tags!r} on the control group, got {group_tags!r}"

    params = paginate(nep, "describe_db_cluster_parameters", "Parameters",
                      DBClusterParameterGroupName=good_ref)
    cp = next(p for p in params if p["ParameterName"] == _PARAM)
    assert cp["ParameterValue"] == good_value, (
        f"expected the control group's {_PARAM!r} to read back {good_value!r}, Neptune reports "
        f"{cp['ParameterValue']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
