"""deploy-healthagent-domain-round-trip-and-delete."""
from __future__ import annotations

import json
import time
from datetime import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-healthagent-domain-round-trip-and-delete"
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

_TEMPLATE_TAGS = {"sim2real-check": CHECK}


def _template(name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Domain": {
                "Type": "AWS::HealthAgent::Domain",
                "Properties": {
                    "Name": name,
                    "Tags": [{"Key": k, "Value": v} for k, v in _TEMPLATE_TAGS.items()],
                },
            },
        },
        "Outputs": {
            "DomainRef": {"Value": {"Ref": "Domain"}},
            "Arn": {"Value": {"Fn::GetAtt": ["Domain", "Arn"]}},
            "DomainId": {"Value": {"Fn::GetAtt": ["Domain", "DomainId"]}},
            "Status": {"Value": {"Fn::GetAtt": ["Domain", "Status"]}},
            "CreatedAt": {"Value": {"Fn::GetAtt": ["Domain", "CreatedAt"]}},
        },
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::HealthAgent::Domain's Ref, GetAtt outputs and declared Name all agree
    with ConnectHealth's own GetDomain; deleting the stack removes the Domain, which GetDomain then
    reports gone.

    Reference: https://docs.aws.amazon.com/connecthealth/latest/APIReference/API_GetDomain.html
    """
    cfn = ctx.client("cloudformation")
    ch = ctx.client("connecthealth")
    name = ctx.unique_name("sim2real-hadom-")
    stack = ctx.unique_name("sim2real-hadomstk-")

    stack_id = create_stack(ctx, cfn, stack, _template(name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE"

    outputs = stack_outputs(cfn, stack_id)
    domain_arn, domain_id = outputs["Arn"], outputs["DomainId"]
    assert outputs["DomainRef"] == domain_arn, (
        f"Ref of the Domain is {outputs['DomainRef']!r}, expected it to equal the Arn {domain_arn!r}"
    )
    assert outputs["Status"] == "ACTIVE", f"GetAtt Status is {outputs['Status']!r}, expected 'ACTIVE'"
    created_at_output = datetime.fromisoformat(outputs["CreatedAt"].replace("Z", "+00:00"))

    resource = cfn.describe_stack_resource(
        StackName=stack_id, LogicalResourceId="Domain")["StackResourceDetail"]
    assert resource["PhysicalResourceId"] == domain_arn, (
        f"the stack resource's PhysicalResourceId is {resource['PhysicalResourceId']!r}, "
        f"expected it to equal the Arn {domain_arn!r}"
    )

    # Independent read: ListDomains by the declared name, never a read keyed by the outputs.
    listed = [(d["domainId"], d["arn"])
              for d in paginate(ch, "list_domains", "domains") if d["name"] == name]
    assert listed == [(domain_id, domain_arn)], (
        f"ListDomains entries named {name!r}: {listed!r}; GetAtt DomainId {domain_id!r}, "
        f"Arn {domain_arn!r}"
    )
    got = ch.get_domain(domainId=domain_id)
    assert got["domainId"] == domain_id, f"GetDomain domainId is {got['domainId']!r}, expected {domain_id!r}"
    assert got["arn"] == domain_arn, f"GetDomain arn is {got['arn']!r}, expected {domain_arn!r}"
    assert got["name"] == name, f"GetDomain name is {got['name']!r}, expected the template's Name {name!r}"
    assert got["status"] == "ACTIVE", f"GetDomain status is {got['status']!r}, expected 'ACTIVE'"
    assert got["encryptionContext"]["encryptionType"] == "AWS_OWNED_KEY", (
        f"GetDomain encryptionContext is {got['encryptionContext']!r}, expected encryptionType "
        f"'AWS_OWNED_KEY' for a Domain declared with no KmsKeyArn"
    )
    assert got["createdAt"] == created_at_output, (
        f"GetDomain createdAt {got['createdAt']!r} does not match the stack's GetAtt CreatedAt "
        f"{created_at_output!r}"
    )

    tag_list = ch.list_tags_for_resource(resourceArn=domain_arn)["tags"]
    user_tags = {k: v for k, v in tag_list.items() if not k.startswith("aws:")}
    # The stack-level sim2real tag, when CloudFormation propagates it, carries the stack name.
    assert user_tags.pop("sim2real", stack) == stack, f"domain tags {tag_list!r}"
    assert user_tags == _TEMPLATE_TAGS, (
        f"ListTagsForResource tags are {tag_list!r}, expected the template's {_TEMPLATE_TAGS!r}"
    )

    delete_stack(cfn, stack_id)
    domain_gone = ("ResourceNotFoundException", f"Domain not found: {domain_id}")
    expect_error(lambda: ch.get_domain(domainId=domain_id), *domain_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
