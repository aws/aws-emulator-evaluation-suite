"""deploy-payment-cryptography-alias-nonexistent-keyarn-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-payment-cryptography-alias-nonexistent-keyarn-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "payment-cryptography"]

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

_REJECTED = (
    "Service returned error code ResourceNotFoundException (Service: PaymentCryptography, "
    "Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "NotFound",
)
_NOT_FOUND = ("ResourceNotFoundException", "")


def _template(alias_name: str, key_arn) -> str:
    """A key-encryption key and an alias whose KeyArn is ``key_arn`` (the key's own, or not)."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Key": {
                "Type": "AWS::PaymentCryptography::Key",
                "Properties": {
                    "Exportable": True,
                    "KeyAttributes": {
                        "KeyAlgorithm": "TDES_2KEY",
                        "KeyClass": "SYMMETRIC_KEY",
                        "KeyUsage": "TR31_K0_KEY_ENCRYPTION_KEY",
                        "KeyModesOfUse": {"Encrypt": True, "Decrypt": True, "Wrap": True,
                                          "Unwrap": True},
                    },
                },
            },
            "Alias": {
                "Type": "AWS::PaymentCryptography::Alias",
                "Properties": {"AliasName": alias_name, "KeyArn": key_arn},
            },
        },
        "Outputs": {
            "AliasRef": {"Value": {"Ref": "Alias"}},
            "KeyArn": {"Value": {"Fn::GetAtt": ["Key", "KeyIdentifier"]}},
        },
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::PaymentCryptography::Alias whose KeyArn names no key is rejected with
    the service's exact ResourceNotFoundException and the alias never exists, while the same
    template with KeyArn naming its own key deploys and the alias reads back bound to that key.

    Reference: https://docs.aws.amazon.com/payment-cryptography/latest/APIReference/API_CreateAlias.html
    """
    pc = ctx.client("payment-cryptography")
    cfn = ctx.client("cloudformation")
    control_alias = f"alias/{ctx.unique_name('sim2real-pcalias-')}"
    bad_alias = f"alias/{ctx.unique_name('sim2real-pcalias-')}"

    # Positive control: the same template, KeyArn given the key the stack creates.
    control_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfnpcalias-"),
                              _template(control_alias, {"Fn::GetAtt": ["Key", "KeyIdentifier"]}))
    status = wait_stack(cfn, control_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    out = stack_outputs(cfn, control_id)
    assert out["AliasRef"] == control_alias, f"control alias Ref {out['AliasRef']!r}"
    listed = [a for a in paginate(pc, "list_aliases", "Aliases", KeyArn=out["KeyArn"])
              if a["AliasName"] == control_alias]
    assert listed == [{"AliasName": control_alias, "KeyArn": out["KeyArn"]}], (
        f"ListAliases of the control key {listed!r}"
    )
    got = pc.get_alias(AliasName=control_alias)["Alias"]
    assert got == {"AliasName": control_alias, "KeyArn": out["KeyArn"]}, f"control alias {got!r}"

    # Only the KeyArn changes: a well-formed ARN in this account and region that no key has.
    partition = control_id.split(":")[1]
    missing_key = f"arn:{partition}:payment-cryptography:{ctx.region}:{ctx.account}:key/0123456789abcdef"
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfnpcalias-"),
                          _template(bad_alias, missing_key))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Alias"), ctx.account)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through Payment Cryptography, by the alias name, before any delete.
    names = [a["AliasName"] for a in paginate(pc, "list_aliases", "Aliases")]
    assert bad_alias not in names, f"the rolled-back alias {bad_alias!r} is listed"
    expect_error(lambda: pc.get_alias(AliasName=bad_alias), *_NOT_FOUND)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
