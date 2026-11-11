"""deploy-mailmanager-duplicate-address-list-name-rejected."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "deploy-mailmanager-duplicate-address-list-name-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "mailmanager"]

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


# The rejected and the control stacks deploy this one template; only whether the second
# address list repeats the first one's name differs.
_TEMPLATE_BODY = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  FirstNameParam:
    Type: String
  SecondNameParam:
    Type: String
Resources:
  First:
    Type: AWS::SES::MailManagerAddressList
    Properties:
      AddressListName: !Ref FirstNameParam
  Second:
    Type: AWS::SES::MailManagerAddressList
    DependsOn: First
    Properties:
      AddressListName: !Ref SecondNameParam
Outputs:
  FirstIdOut:
    Value: !Ref First
  SecondIdOut:
    Value: !Ref Second
"""


def _parameters(first: str, second: str) -> list[dict]:
    return [
        {"ParameterKey": "FirstNameParam", "ParameterValue": first},
        {"ParameterKey": "SecondNameParam", "ParameterValue": second},
    ]


def _listed(mm, op: str, key: str, name_field: str, name: str) -> list[dict]:
    """Every entry a paginated MailManager List call returns under ``name``."""
    return [item for item in paginate(mm, op, key) if item[name_field] == name]


def _user_tags(mm, arn: str) -> dict:
    tag_list = mm.list_tags_for_resource(ResourceArn=arn)["Tags"]
    return {t["Key"]: t["Value"] for t in tag_list if not t["Key"].startswith("aws:")}


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second MailManagerAddressList repeating a taken name fails the stack with MailManager's
    conflict and the rollback leaves no list; the same template with two distinct names deploys.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ses-mailmanageraddresslist.html
    """
    cfn = ctx.client("cloudformation")
    mm = ctx.client("mailmanager")

    stack_name = ctx.unique_name("sim2real-cfn-mm-dup-")
    shared_name = ctx.unique_name("sim2real-cfn-mm-dupname-")

    stack_id = create_stack(ctx, cfn, stack_name, _TEMPLATE_BODY,
                            Parameters=_parameters(shared_name, shared_name))
    status = wait_stack(cfn, stack_id)
    assert status == "ROLLBACK_COMPLETE", f"stack create ended in {status!r}, not ROLLBACK_COMPLETE"

    reasons = [
        handler_reason(e.get("ResourceStatusReason"), ctx.account)
        for e in stack_events(cfn, stack_id)
        if e["LogicalResourceId"] == "Second" and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    expected_reason = (
        f"SimpleAddressList name {shared_name} already exists in account <account> "
        "(Service: MailManager, Status Code: 409, Request ID: <id>) (SDK Attempt Count: <n>)",
        "AlreadyExists",
    )
    assert reasons == [expected_reason], (
        f"Second's CREATE_FAILED reasons (masked) were {reasons!r}, expected [{expected_reason!r}]"
    )

    # Rollback removed the first list too: MailManager lists nothing under the shared name.
    left = _listed(mm, "list_address_lists", "AddressLists", "AddressListName", shared_name)
    assert left == [], f"the rolled-back stack left address lists named {shared_name!r}: {left!r}"

    delete_stack(cfn, stack_id)

    control_stack = ctx.unique_name("sim2real-cfn-mm-dupctl-")
    first_name = ctx.unique_name("sim2real-cfn-mm-dupctla-")
    second_name = ctx.unique_name("sim2real-cfn-mm-dupctlb-")
    control_id = create_stack(ctx, cfn, control_stack, _TEMPLATE_BODY,
                              Parameters=_parameters(first_name, second_name))
    control_status = wait_stack(cfn, control_id)
    assert control_status == "CREATE_COMPLETE", (
        f"control stack create ended in {control_status!r}: "
        f"{decisive_rows(stack_events(cfn, control_id))!r}"
    )
    outputs = stack_outputs(cfn, control_id)
    for name, ref in ((first_name, outputs["FirstIdOut"]), (second_name, outputs["SecondIdOut"])):
        listed = [e["AddressListId"] for e in _listed(mm, "list_address_lists", "AddressLists", "AddressListName", name)]
        assert listed == [ref], f"ListAddressLists ids under {name!r} were {listed!r}, expected [Ref {ref!r}]"
        control = mm.get_address_list(AddressListId=ref)
        assert control["AddressListName"] == name, (
            f"GetAddressList name was {control['AddressListName']!r}, expected {name!r}"
        )
        found = _user_tags(mm, control["AddressListArn"])
        assert found == {"sim2real": control_stack}, (
            f"the control address list's tags (aws: keys dropped) were {found!r}, expected the stack's tag"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
