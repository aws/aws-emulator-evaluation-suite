"""deploy-securityagent-private-connection-lifecycle."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-securityagent-private-connection-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "securityagent"]

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


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


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

_NOT_FOUND = ("ResourceNotFoundException", "Private Connection not found: null")
# SecurityAgent fails a connection whose subnets EC2 has not yet propagated to it (its
# failureMessage reads "The subnet ID ... does not exist"); the handler reports only this.
_SUBNETS_NOT_YET_VISIBLE = ("Private connection creation failed: status CREATE_FAILED",
                            "NotStabilized")
_ATTEMPTS = 3
# One deadline for the whole run under the suite's 1800 s check budget: the create and every
# connection update take at most what is left once the stack delete (_DELETE_BUDGET_S) and the
# NotFound poll after it (_GONE_S) are set aside.
_RUN_BUDGET_S = 1740.0
_GONE_S = 120.0


def _left(deadline):
    """Seconds until ``deadline`` (a time.monotonic() value)."""
    return deadline - time.monotonic()


def _template(pc_name, host_address):
    """The VPC and two subnets, plus the private connection unless ``pc_name`` is None."""
    resources = {
        "VPC": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.201.0.0/16"}},
        "SubA": {"Type": "AWS::EC2::Subnet", "Properties": {
            "VpcId": {"Ref": "VPC"}, "CidrBlock": "10.201.1.0/24",
            "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
        }},
        "SubB": {"Type": "AWS::EC2::Subnet", "Properties": {
            "VpcId": {"Ref": "VPC"}, "CidrBlock": "10.201.2.0/24",
            "AvailabilityZone": {"Fn::Select": [1, {"Fn::GetAZs": ""}]},
        }},
    }
    outputs = {"VpcRef": {"Value": {"Ref": "VPC"}}}
    if pc_name is not None:
        resources["PC"] = {
            "Type": "AWS::SecurityAgent::PrivateConnection",
            "Properties": {
                "PrivateConnectionName": pc_name,
                "Mode": {"ServiceManaged": {
                    "VpcId": {"Ref": "VPC"},
                    "SubnetIds": [{"Ref": "SubA"}, {"Ref": "SubB"}],
                    "HostAddress": host_address,
                }},
            },
        }
        outputs.update({
            "PCRef": {"Value": {"Ref": "PC"}},
            "PCStatus": {"Value": {"Fn::GetAtt": ["PC", "Status"]}},
            "PCResourceGatewayId": {"Value": {"Fn::GetAtt": ["PC", "ResourceGatewayId"]}},
            "PCHostAddress": {"Value": {"Fn::GetAtt": ["PC", "HostAddress"]}},
            "PCVpcId": {"Value": {"Fn::GetAtt": ["PC", "VpcId"]}},
        })
    return json.dumps({"Resources": resources, "Outputs": outputs})


def _add_connection(ctx, cf, stack_id, host_address, deadline):
    """Update the network stack to add the connection; returns its name.

    The subnets exist before the connection is asked for. A connection refused only because
    SecurityAgent cannot see the subnets yet is retried under a fresh name, up to _ATTEMPTS; each
    update's rollback leaves the subnets older.
    """
    for attempt in range(1, _ATTEMPTS + 1):
        # The provider derives an internal resource gateway name of
        # "continuum-<PrivateConnectionName>" capped at 40 characters, so the name stays short.
        pc_name = ctx.unique_name("sim2real-pc-")
        cf.update_stack(StackName=stack_id, TemplateBody=_template(pc_name, host_address))
        status = wait_stack(cf, stack_id, timeout_s=_left(deadline))
        if status == "UPDATE_COMPLETE":
            return pc_name
        events = stack_events(cf, stack_id)
        reasons = [e.get("ResourceStatusReason") for e in events
                   if (e["LogicalResourceId"], e["ResourceStatus"]) == ("PC", "CREATE_FAILED")]
        m = _HANDLER_REASON.match(reasons[-1] if reasons else "")
        transient = m is not None and (m["message"], m["code"]) == _SUBNETS_NOT_YET_VISIBLE
        if status != "UPDATE_ROLLBACK_COMPLETE" or not transient or attempt == _ATTEMPTS:
            raise AssertionError(f"expected UPDATE_COMPLETE on attempt {attempt}, got "
                                 f"{status!r}: {decisive_rows(events)!r} {reasons!r}")
    raise AssertionError("unreachable")


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::SecurityAgent::PrivateConnection is real at SecurityAgent: its
    Ref is the connection Arn, its VPC is the template's, its GetAtt values match the service's own
    answer, and deleting the stack removes the connection, not just the stack."""
    cf = ctx.client("cloudformation")
    sa = ctx.client("securityagent")
    stack_name = ctx.unique_name("sim2real-behav-cfn-sa-pc-")
    host_address = "sim2real-probe.internal.example.com"

    deadline = time.monotonic() + _RUN_BUDGET_S - _DELETE_BUDGET_S - _GONE_S
    stack_id = create_stack(ctx, cf, stack_name, _template(None, host_address))
    created = wait_stack(cf, stack_id, timeout_s=_left(deadline))
    assert created == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    pc_name = _add_connection(ctx, cf, stack_id, host_address, deadline)

    outputs = stack_outputs(cf, stack_id)
    partition = stack_id.split(":")[1]
    expected_arn = (
        f"arn:{partition}:securityagent:{ctx.region}:{ctx.account}:private-connection/{pc_name}"
    )
    assert outputs["PCRef"] == expected_arn, f"Ref of PC was {outputs['PCRef']!r}"
    assert outputs["PCStatus"] == "ACTIVE", f"GetAtt Status was {outputs['PCStatus']!r}"

    vpc_id = outputs["VpcRef"]

    # Independent read at the owning service: SecurityAgent's own record of the connection.
    got = sa.describe_private_connection(privateConnectionName=pc_name)
    assert got["name"] == pc_name, f"DescribePrivateConnection name {got['name']!r}, expected {pc_name!r}"
    assert got["status"] == "ACTIVE", f"DescribePrivateConnection status {got['status']!r}"
    assert got["hostAddress"] == host_address, (
        f"DescribePrivateConnection hostAddress {got['hostAddress']!r}, expected {host_address!r}"
    )
    assert got["hostAddress"] == outputs["PCHostAddress"], (
        f"DescribePrivateConnection hostAddress {got['hostAddress']!r} does not match the stack's "
        f"GetAtt HostAddress {outputs['PCHostAddress']!r}"
    )
    assert got["resourceGatewayId"] == outputs["PCResourceGatewayId"], (
        f"DescribePrivateConnection resourceGatewayId {got['resourceGatewayId']!r} does not match "
        f"the stack's GetAtt ResourceGatewayId {outputs['PCResourceGatewayId']!r}"
    )
    assert got["vpcId"] == vpc_id, (
        f"DescribePrivateConnection vpcId {got['vpcId']!r} is not the template VPC {vpc_id!r}"
    )
    assert got["vpcId"] == outputs["PCVpcId"], (
        f"DescribePrivateConnection vpcId {got['vpcId']!r} does not match the stack's GetAtt VpcId "
        f"{outputs['PCVpcId']!r}"
    )

    delete_stack(cf, stack_id)

    until_raises(lambda: sa.describe_private_connection(privateConnectionName=pc_name), _GONE_S)
    expect_error(lambda: sa.describe_private_connection(privateConnectionName=pc_name), *_NOT_FOUND)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
