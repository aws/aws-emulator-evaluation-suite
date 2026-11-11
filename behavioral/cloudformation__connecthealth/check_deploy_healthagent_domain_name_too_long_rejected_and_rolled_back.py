"""deploy-healthagent-domain-name-too-long-rejected-and-rolled-back."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-healthagent-domain-name-too-long-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "connecthealth"]

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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


# ---- Check-specific: the template, then run(). ----

_STACK_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of "
    "issues with resource and property details, resolve each error, then retry the operation."
)
_BAD_NAME_LEN = 65  # one over the schema's 64-character maximum for Name


def _template(name: str) -> str:
    """The Domain stack; the rejected and the control stacks differ only in Name."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Domain": {"Type": "AWS::HealthAgent::Domain", "Properties": {"Name": name}},
        },
        "Outputs": {
            "DomainRef": {"Value": {"Ref": "Domain"}},
            "DomainId": {"Value": {"Fn::GetAtt": ["Domain", "DomainId"]}},
        },
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::HealthAgent::Domain whose Name exceeds the schema's 64-character
    maximum is rejected before any Domain is created, and the stack rolls back; the identical
    mechanism with a valid Name still creates and reads back through ConnectHealth.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-healthagent-domain.html
    """
    cfn = ctx.client("cloudformation")
    ch = ctx.client("connecthealth")
    bad_stack = ctx.unique_name("sim2real-hadombad-")

    bad_id = create_stack(ctx, cfn, bad_stack, _template("x" * _BAD_NAME_LEN))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack {bad_stack!r} ended {status!r}, expected ROLLBACK_COMPLETE"
    )

    failed = [e.get("ResourceStatusReason") for e in stack_events(cfn, bad_id)
              if e["LogicalResourceId"] == bad_stack and e["ResourceStatus"] == "CREATE_FAILED"]
    assert failed == [_STACK_REASON], (
        f"expected the stack's CREATE_FAILED reasons {[_STACK_REASON]!r}, got {failed!r}"
    )
    found = validation_rows(cfn, bad_id)
    want_errors = [(
        "Domain", "PROPERTY_VALIDATION", "FAILED", "FAIL",
        f"#/Name: expected maxLength: 64, actual: {_BAD_NAME_LEN}", "/Resources/Domain/Properties/Name",
    )]
    assert found == want_errors, f"validation errors of the create: expected {want_errors!r}, got {found!r}"
    types = [e.get("ResourceType") for e in paginate(
        cfn, "describe_events", "OperationEvents", StackName=bad_id)
        if e.get("EventType") == "VALIDATION_ERROR"]
    assert types == ["AWS::HealthAgent::Domain"], f"validation error resource types {types!r}"

    resources = cfn.describe_stack_resources(StackName=bad_id)["StackResources"]
    assert resources == [], (
        f"expected no resource was ever created for the rejected stack, got {resources!r}"
    )

    delete_stack(cfn, bad_id)

    # Positive control: the identical mechanism, given a valid Name, creates a real Domain.
    good_stack = ctx.unique_name("sim2real-hadomgood-")
    good_name = ctx.unique_name("sim2real-hadomok-")
    good_id = create_stack(ctx, cfn, good_stack, _template(good_name))
    good_status = wait_stack(cfn, good_id)
    assert good_status == "CREATE_COMPLETE", (
        f"the control stack {good_stack!r} ended {good_status!r}, expected CREATE_COMPLETE"
    )
    good_outputs = stack_outputs(cfn, good_id)
    good_domain_id = good_outputs["DomainId"]
    control = ch.get_domain(domainId=good_domain_id)
    assert control["arn"] == good_outputs["DomainRef"], (
        f"expected the control Domain's Ref to be GetDomain's arn, got Ref={good_outputs['DomainRef']!r} "
        f"arn={control['arn']!r}"
    )
    assert control["name"] == good_name, (
        f"expected the control Domain {good_domain_id!r} to carry Name {good_name!r}, "
        f"ConnectHealth reports {control['name']!r}"
    )
    assert control["status"] == "ACTIVE", (
        f"expected the control Domain to be ACTIVE, ConnectHealth reports {control['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
