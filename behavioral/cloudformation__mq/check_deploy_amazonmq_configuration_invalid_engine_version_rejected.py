"""deploy-amazonmq-configuration-invalid-engine-version-rejected."""
from __future__ import annotations

import base64
import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-amazonmq-configuration-invalid-engine-version-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "mq"]

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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


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

_BAD_ENGINE_VERSION = "99.99"
_PURGE_PERIOD = "3"


def _data(purge_period: str) -> str:
    xml = (
        '<broker xmlns="http://activemq.apache.org/schema/core" '
        f'schedulePeriodForDestinationPurge="{purge_period}"></broker>'
    )
    return base64.b64encode(xml.encode()).decode()


def _template(name: str, engine_version: str) -> str:
    """One configuration; only its EngineVersion varies between the control and the negative."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Cfg": {
                "Type": "AWS::AmazonMQ::Configuration",
                "Properties": {
                    "Name": name,
                    "EngineType": "ACTIVEMQ",
                    "EngineVersion": engine_version,
                    "Data": _data(_PURGE_PERIOD),
                    "Tags": [{"Key": "sim2real-mqcfg", "Value": name}],
                },
            },
        },
        "Outputs": {"CfgId": {"Value": {"Ref": "Cfg"}}},
    })


def _list_configurations(mq) -> list[dict]:
    items: list[dict] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        page = mq.list_configurations(**kwargs)
        items.extend(page["Configurations"])
        token = page.get("NextToken")
        if not token:
            return items


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::AmazonMQ::Configuration with an EngineVersion MQ does not offer for
    ACTIVEMQ rolls back with MQ's exact handler error and no configuration exists, while the
    same template with an offered version deploys and reads back.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-amazonmq-configuration.html
    """
    cfn = ctx.client("cloudformation")
    mq = ctx.client("mq")
    versions = sorted(
        (v["Name"] for v in mq.describe_broker_engine_types(EngineType="ACTIVEMQ")
         ["BrokerEngineTypes"][0]["EngineVersions"]),
        reverse=True,
    )
    assert versions and _BAD_ENGINE_VERSION not in versions, f"ACTIVEMQ versions {versions!r}"

    bad_name = ctx.unique_name("sim2real-mqcfgbad-")
    bad_stack = ctx.unique_name("sim2real-mqcfgbad-stack-")
    bad_id = create_stack(ctx, cfn, bad_stack, _template(bad_name, _BAD_ENGINE_VERSION))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cfn, bad_id)
    assert rows == [], f"refused by early validation, not by the handler: {rows!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Cfg"), ctx.account,
                         bad_name, bad_stack)
    want = (
        f"Broker engine version [{_BAD_ENGINE_VERSION}] is invalid for broker engine type "
        f"[ACTIVEMQ]. Valid values: [{', '.join(versions)}]. (Service: Mq, Status Code: 400, "
        "Request ID: <id>) (SDK Attempt Count: <n>)",
        "GeneralServiceException",
    )
    assert got == want, f"handler reason {got!r}, expected {want!r}"
    # Rollback absence through MQ, by the name the configuration would have, before any delete.
    listed = [c for c in _list_configurations(mq) if c["Name"] == bad_name]
    assert listed == [], f"the rolled-back configuration is listed: {listed!r}"

    # Positive control: the same template with the newest version MQ offers.
    good_name = ctx.unique_name("sim2real-mqcfggood-")
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-mqcfggood-stack-"),
                           _template(good_name, versions[0]))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    ref = stack_outputs(cfn, good_id)["CfgId"]
    listed = [c for c in _list_configurations(mq) if c["Name"] == good_name]
    got = [(c["Id"], c["EngineType"], c["EngineVersion"]) for c in listed]
    assert got == [(ref, "ActiveMQ", versions[0])], f"control configuration listed as {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
