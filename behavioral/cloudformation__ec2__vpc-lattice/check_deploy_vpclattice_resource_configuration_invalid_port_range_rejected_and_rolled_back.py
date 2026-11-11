"""deploy-vpclattice-resource-configuration-invalid-port-range-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-vpclattice-resource-configuration-invalid-port-range-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2", "vpc-lattice"]

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


def is_subsequence(want, rows):
    """True when ``want`` occurs in ``rows`` in order (gaps allowed)."""
    it = iter(rows)
    return all(w in it for w in want)


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

_VPC_CIDR = "10.121.0.0/16"
_SUBNET_CIDR = "10.121.0.0/24"
_IP_RESOURCE = "10.121.0.50"
_BAD_PORT_RANGE = "100-50"
_GOOD_PORT_RANGE = "443"
_REJECTED = (
    "100-50 is not a valid port range (Service: VpcLattice, Status Code: 400, Request ID: <id>) "
    "(SDK Attempt Count: <n>)",
    "InvalidRequest",
)
_GATEWAY_ARN = re.compile(r"arn:aws[a-z-]*:vpc-lattice:[a-z0-9-]+:\d{12}:resourcegateway/(rgw-[0-9a-z]+)")


def _gateway_template(tag_value: str, az: str, rg_name: str, rc_name: str,
                       vpc_cidr: str, subnet_cidr: str, ip_resource: str, port_range: str) -> str:
    t = [{"Key": "sim2real-check", "Value": tag_value}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": vpc_cidr, "Tags": t}},
            "Subnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": subnet_cidr,
                                "AvailabilityZone": az, "Tags": t},
            },
            "Sg": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {"GroupDescription": "sim2real vpc lattice port range sg",
                                "VpcId": {"Ref": "Vpc"}, "Tags": t},
            },
            "ResourceGateway": {
                "Type": "AWS::VpcLattice::ResourceGateway",
                "Properties": {
                    "Name": rg_name,
                    "VpcIdentifier": {"Ref": "Vpc"},
                    "SubnetIds": [{"Ref": "Subnet"}],
                    "SecurityGroupIds": [{"Ref": "Sg"}],
                    "Tags": t,
                },
            },
            "ResourceConfiguration": {
                "Type": "AWS::VpcLattice::ResourceConfiguration",
                "Properties": {
                    "Name": rc_name,
                    "ResourceConfigurationType": "SINGLE",
                    "ResourceGatewayId": {"Fn::GetAtt": ["ResourceGateway", "Id"]},
                    "ResourceConfigurationDefinition": {"IpResource": ip_resource},
                    "PortRanges": [port_range],
                    "Tags": t,
                },
            },
        },
        "Outputs": {
            "ResourceConfigurationId": {"Value": {"Fn::GetAtt": ["ResourceConfiguration", "Id"]}},
        },
    })


def _usable_az(ec2) -> str:
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert usable, "no available Availability Zone in this region"
    return usable[0]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::VpcLattice::ResourceConfiguration with FromPort greater than ToPort
    in a PortRanges entry is rejected by VPC Lattice with its own exact error, and the stack
    rolls back the gateway and VPC it had already created; a valid port range still succeeds.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-vpclattice-resourceconfiguration.html
    """
    ec2 = ctx.client("ec2")
    vl = ctx.client("vpc-lattice")
    cfn = ctx.client("cloudformation")
    az = _usable_az(ec2)

    bad_stack = ctx.unique_name("sim2real-vpclbad-")
    bad_rg_name = ctx.unique_name("sim2real-vpclbad-rg-")
    bad_rc_name = ctx.unique_name("sim2real-vpclbad-rc-")
    bad_id = create_stack(ctx, cfn, bad_stack, _gateway_template(
        CHECK, az, bad_rg_name, bad_rc_name, _VPC_CIDR, _SUBNET_CIDR, _IP_RESOURCE,
        _BAD_PORT_RANGE,
    ))
    status = wait_stack(cfn, bad_id, timeout_s=600.0)
    assert status == "ROLLBACK_COMPLETE", f"stack {bad_stack!r} ended {status!r}, expected ROLLBACK_COMPLETE"

    events = stack_events(cfn, bad_id)
    got_error = handler_reason(failed_reason(events, "ResourceConfiguration"), ctx.account)
    assert got_error == _REJECTED, (
        f"ResourceConfiguration CREATE_FAILED reason: expected {_REJECTED!r}, got {got_error!r}"
    )

    resources = cfn.describe_stack_resources(StackName=bad_id)["StackResources"]
    by_logical = {r["LogicalResourceId"]: r for r in resources}
    assert by_logical["ResourceConfiguration"].get("PhysicalResourceId") is None, (
        f"a ResourceConfiguration that failed to create should carry no PhysicalResourceId, got "
        f"{by_logical['ResourceConfiguration'].get('PhysicalResourceId')!r}"
    )
    rg_arn = by_logical["ResourceGateway"]["PhysicalResourceId"]
    vpc_id = by_logical["Vpc"]["PhysicalResourceId"]
    rg_match = _GATEWAY_ARN.fullmatch(rg_arn)
    assert rg_match is not None, f"ResourceGateway physical id is not a resource gateway ARN: {rg_arn!r}"
    rg_id = rg_match[1]

    want_rows = [("Vpc", "CREATE_COMPLETE"), ("ResourceGateway", "CREATE_COMPLETE"),
                 ("ResourceConfiguration", "CREATE_FAILED"), ("ResourceGateway", "DELETE_COMPLETE"),
                 ("Vpc", "DELETE_COMPLETE")]
    rows = decisive_rows(events)
    assert is_subsequence(want_rows, rows), (
        f"expected the rolled-back stack's events {want_rows!r} in order; decisive rows {rows!r}"
    )

    rg_gone = ("ResourceNotFoundException", f"Resource not found: {rg_id}")
    expect_error(lambda: vl.get_resource_gateway(resourceGatewayIdentifier=rg_arn), *rg_gone)
    vpc_gone = ("InvalidVpcID.NotFound", f"The vpc ID '{vpc_id}' does not exist")
    expect_error(lambda: ec2.describe_vpcs(VpcIds=[vpc_id]), *vpc_gone)

    # Positive control: the identical template, given a valid port range, succeeds (the
    # rollback removed the rejected stack's VPC, so the control reuses its CIDRs).
    good_stack = ctx.unique_name("sim2real-vpclgood-")
    good_rg_name = ctx.unique_name("sim2real-vpclgood-rg-")
    good_rc_name = ctx.unique_name("sim2real-vpclgood-rc-")
    good_id = create_stack(ctx, cfn, good_stack, _gateway_template(
        CHECK, az, good_rg_name, good_rc_name, _VPC_CIDR, _SUBNET_CIDR, _IP_RESOURCE,
        _GOOD_PORT_RANGE,
    ))
    good_status = wait_stack(cfn, good_id, timeout_s=600.0)
    assert good_status == "CREATE_COMPLETE", (
        f"the control stack {good_stack!r} ended {good_status!r}, expected CREATE_COMPLETE"
    )
    good_rc_id = stack_outputs(cfn, good_id)["ResourceConfigurationId"]
    control = vl.get_resource_configuration(resourceConfigurationIdentifier=good_rc_id)
    assert control["portRanges"] == [_GOOD_PORT_RANGE], (
        f"expected the control ResourceConfiguration portRanges {[_GOOD_PORT_RANGE]!r}, "
        f"VPC Lattice reports {control['portRanges']!r}"
    )
    assert control["name"] == good_rc_name, (
        f"expected the control ResourceConfiguration name {good_rc_name!r}, got {control['name']!r}"
    )
    assert control["type"] == "SINGLE", (
        f"expected the control ResourceConfiguration type SINGLE, got {control['type']!r}"
    )
    assert control["resourceConfigurationDefinition"] == {
        "ipResource": {"ipAddress": _IP_RESOURCE}
    }, (
        f"expected the control definition's ipResource {_IP_RESOURCE!r}, got "
        f"{control['resourceConfigurationDefinition']!r}"
    )
    assert control["status"] == "ACTIVE", (
        f"expected the control ResourceConfiguration status ACTIVE, got {control['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
