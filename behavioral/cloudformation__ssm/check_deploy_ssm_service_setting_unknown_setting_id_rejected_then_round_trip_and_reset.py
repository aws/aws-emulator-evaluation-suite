"""deploy-ssm-service-setting-unknown-setting-id-rejected-then-round-trip-and-reset."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-ssm-service-setting-unknown-setting-id-rejected-then-round-trip-and-reset"
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

#: An account setting no other check's outcome depends on: it raises Parameter Store's throughput
#: quota (and its billing), and changes no parameter's tier, type or answer.
_SETTING_ID = "/ssm/parameter-store/high-throughput-enabled"
_DEFAULT_VALUE = "false"
_CUSTOM_VALUE = "true"
_RESET_WAIT_S = 60.0
_BAD_SETTING_ID = "/ssm/parameter-store/does-not-exist-setting"
_REJECTED = (
    " (Service: SSM; Operation: UpdateServiceSetting; Status Code: 400; "
    "Error Code: ServiceSettingNotFound; Request ID: <id>)",
    "NotFound",
)


def _template(setting_id: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Setting": {
                "Type": "AWS::SSM::ServiceSetting",
                "Properties": {"SettingId": setting_id, "SettingValue": _CUSTOM_VALUE},
            },
        },
        "Outputs": {
            "Ref": {"Value": {"Ref": "Setting"}},
            "Arn": {"Value": {"Fn::GetAtt": ["Setting", "Arn"]}},
            "Status": {"Value": {"Fn::GetAtt": ["Setting", "Status"]}},
            "LastModifiedDate": {"Value": {"Fn::GetAtt": ["Setting", "LastModifiedDate"]}},
            "LastModifiedUser": {"Value": {"Fn::GetAtt": ["Setting", "LastModifiedUser"]}},
        },
    })


def _iso_z(dt) -> str:
    """CFN's Fn::GetAtt millisecond-precision form for an SSM timestamp."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control", "resource:account-singleton:ssm-service-settings")
def run(ctx) -> None:
    """An unknown AWS::SSM::ServiceSetting SettingId is refused by SSM and rolls back leaving the
    real setting untouched; the same template with a valid SettingId customizes it, with Ref, every
    GetAtt and the value reading back through SSM, and deleting the stack restores the prior record.
    """
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    baseline = ssm.get_service_setting(SettingId=_SETTING_ID)["ServiceSetting"]
    got = (baseline["Status"], baseline["SettingValue"])
    assert got == ("Default", _DEFAULT_VALUE), (
        f"precondition: {_SETTING_ID!r} must start at (Default, {_DEFAULT_VALUE!r}) so the stack's "
        f"delete restores it, got {got!r}"
    )

    # Negative: an unknown SettingId (same template) is refused by SSM itself.
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-ssmsetbad-"),
                          _template(_BAD_SETTING_ID))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Setting"), ctx.account)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"
    unchanged = ssm.get_service_setting(SettingId=_SETTING_ID)["ServiceSetting"]
    got = (unchanged["SettingValue"], unchanged["LastModifiedDate"])
    assert got == (_DEFAULT_VALUE, baseline["LastModifiedDate"]), (
        f"the rejected stack touched {_SETTING_ID!r}: (value, LastModifiedDate) {got!r}"
    )

    # Positive control: the valid SettingId customizes the setting and reads back.
    # The account-wide setting is restored even if the stack delete handler does not reset it;
    # registered first, it runs after the stack's own cleanup.
    ctx.on_cleanup(lambda: ssm.reset_service_setting(SettingId=_SETTING_ID))
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-ssmsetgood-"),
                           _template(_SETTING_ID))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    outputs = stack_outputs(cfn, good_id)
    live = ssm.get_service_setting(SettingId=_SETTING_ID)["ServiceSetting"]
    partition = good_id.split(":")[1]
    arn = f"arn:{partition}:ssm:{ctx.region}:{ctx.account}:servicesetting{_SETTING_ID}"
    got = {k: outputs[k] for k in ("Ref", "Arn", "Status", "LastModifiedUser", "LastModifiedDate")}
    want = {"Ref": arn, "Arn": arn, "Status": "Customized",
            "LastModifiedUser": live["LastModifiedUser"],
            "LastModifiedDate": _iso_z(live["LastModifiedDate"])}
    assert got == want, f"Ref/GetAtts {got!r}, expected {want!r}"
    got = (live["ARN"], live["Status"], live["SettingValue"])
    assert got == (arn, "Customized", _CUSTOM_VALUE), f"SSM reads {got!r}"

    delete_stack(cfn, good_id)
    # The delete handler's reset reaches GetServiceSetting eventually: a bounded poll to the
    # baseline record, then the exact compare.
    keys = ("Status", "SettingValue", "LastModifiedDate", "LastModifiedUser")
    want = {k: baseline.get(k) for k in keys}
    deadline = time.monotonic() + _RESET_WAIT_S
    while True:
        reset = ssm.get_service_setting(SettingId=_SETTING_ID)["ServiceSetting"]
        got = {k: reset.get(k) for k in keys}
        if got == want or time.monotonic() > deadline:
            break
        time.sleep(2)
    assert got == want, f"after the delete {_SETTING_ID!r} reads {got!r}, was {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
