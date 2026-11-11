"""deploy-cfn-nfwr-firewall-and-logging-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-nfwr-firewall-and-logging-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2", "network-firewall"]

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

_VPC_CIDR = "10.70.0.0/16"
_SUBNET_CIDR = "10.70.1.0/24"
# A firewall takes several minutes PROVISIONING -> READY, so this check deploys one stack only.
_CREATE_DEADLINE_S = 780.0
_DESCRIPTION = "sim2real cloudformation provisioning check"
_POLICY = {
    "StatelessDefaultActions": ["aws:forward_to_sfe"],
    "StatelessFragmentDefaultActions": ["aws:forward_to_sfe"],
}
_NOT_FOUND = "No object with the provided name or resource identifier was found"


def _template(name, log_group, az, with_logging=True):
    def t(kind):
        return [{"Key": "sim2real-nfw", "Value": f"{name}-{kind}"}]

    resources = {
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR, "Tags": t("vpc")}},
        "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDR, "AvailabilityZone": az,
            "Tags": t("subnet"),
        }},
        "Policy": {"Type": "AWS::NetworkFirewall::FirewallPolicy", "Properties": {
            "FirewallPolicyName": f"{name}-policy", "FirewallPolicy": dict(_POLICY),
            "Tags": t("policy"),
        }},
        "Firewall": {"Type": "AWS::NetworkFirewall::Firewall", "Properties": {
            "FirewallName": f"{name}-fw",
            "FirewallPolicyArn": {"Ref": "Policy"},
            "VpcId": {"Ref": "Vpc"},
            "SubnetMappings": [{"SubnetId": {"Ref": "Subnet"}}],
            "Description": _DESCRIPTION,
            "DeleteProtection": False,
            "SubnetChangeProtection": False,
            "FirewallPolicyChangeProtection": False,
            "Tags": t("fw"),
        }},
        "LogGroup": {"Type": "AWS::Logs::LogGroup", "Properties": {
            "LogGroupName": log_group, "RetentionInDays": 1,
        }},
    }
    outputs = {
        "SubnetId": {"Value": {"Ref": "Subnet"}},
        "PolicyArn": {"Value": {"Ref": "Policy"}},
        "FirewallArn": {"Value": {"Ref": "Firewall"}},
        "FirewallId": {"Value": {"Fn::GetAtt": ["Firewall", "FirewallId"]}},
        "FirewallEndpointIds": {"Value": {"Fn::Join": [",", {"Fn::GetAtt": ["Firewall",
                                                                            "EndpointIds"]}]}},
    }
    if with_logging:
        resources["Logging"] = {"Type": "AWS::NetworkFirewall::LoggingConfiguration",
                                "Properties": {
            "FirewallArn": {"Ref": "Firewall"},
            "LoggingConfiguration": {"LogDestinationConfigs": [{
                "LogType": "FLOW", "LogDestinationType": "CloudWatchLogs",
                "LogDestination": {"logGroup": {"Ref": "LogGroup"}},
            }]},
        }}
        outputs["LoggingRef"] = {"Value": {"Ref": "Logging"}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _own_tags(tag_list):
    return {t["Key"]: t["Value"] for t in tag_list or [] if not t["Key"].startswith("aws:")}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation Network Firewall, policy and logging configuration read back as templated.

    An update dropping the logging configuration empties it on the same firewall; the stack's
    delete removes the firewall, its policy, subnet and VPC.
    """
    cf = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    nfw = ctx.client("network-firewall")
    stack = ctx.unique_name("sim2real-nfwrstack-")
    name = ctx.unique_name("sim2real-nfwr-")
    log_group = ctx.unique_name("sim2real-nfwr-logs-")
    zones = ec2.describe_availability_zones(Filters=[
        {"Name": "state", "Values": ["available"]},
        {"Name": "zone-type", "Values": ["availability-zone"]},
    ])["AvailabilityZones"]
    assert zones, "no available Availability Zone in this region"
    az = sorted(z["ZoneName"] for z in zones)[0]

    stack_id = create_stack(ctx, cf, stack, _template(name, log_group, az))
    status = wait_stack(cf, stack_id, timeout_s=_CREATE_DEADLINE_S)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)

    # VPC and subnet through EC2, found by the template's own tag, not by the Ref.
    vpcs = paginate(ec2, "describe_vpcs", "Vpcs",
                    Filters=[{"Name": "tag:sim2real-nfw", "Values": [f"{name}-vpc"]}])
    assert [(v["CidrBlock"], _own_tags(v.get("Tags"))) for v in vpcs] == [
        (_VPC_CIDR, {"sim2real": stack, "sim2real-nfw": f"{name}-vpc"})], f"VPCs {vpcs!r}"
    vpc_id = vpcs[0]["VpcId"]
    subnets = paginate(ec2, "describe_subnets", "Subnets",
                       Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    got_subnets = [(s["SubnetId"], s["CidrBlock"], s["AvailabilityZone"],
                    _own_tags(s.get("Tags"))) for s in subnets]
    assert got_subnets == [(out["SubnetId"], _SUBNET_CIDR, az,
                            {"sim2real": stack, "sim2real-nfw": f"{name}-subnet"})], (
        f"subnets {got_subnets!r}"
    )

    # Firewall Ref against an independent ListFirewalls by the VPC.
    listed = paginate(nfw, "list_firewalls", "Firewalls", VpcIds=[vpc_id])
    assert [(f["FirewallName"], f["FirewallArn"]) for f in listed] == [
        (f"{name}-fw", out["FirewallArn"])], f"ListFirewalls {listed!r}"
    got = nfw.describe_firewall(FirewallName=f"{name}-fw")
    fw, fw_status = got["Firewall"], got["FirewallStatus"]
    want_fw = {
        "FirewallName": f"{name}-fw", "FirewallArn": out["FirewallArn"],
        "FirewallId": out["FirewallId"], "FirewallPolicyArn": out["PolicyArn"],
        "VpcId": vpc_id, "SubnetMappings": [out["SubnetId"]], "Description": _DESCRIPTION,
        "DeleteProtection": False, "SubnetChangeProtection": False,
        "FirewallPolicyChangeProtection": False, "NumberOfAssociations": 0,
        "Tags": {"sim2real": stack, "sim2real-nfw": f"{name}-fw"},
    }
    got_fw = {k: fw.get(k) for k in want_fw}
    got_fw["SubnetMappings"] = [m["SubnetId"] for m in fw["SubnetMappings"]]
    got_fw["Tags"] = _own_tags(fw.get("Tags"))
    assert got_fw == want_fw, f"DescribeFirewall {got_fw!r}, expected {want_fw!r}"
    assert fw_status["Status"] == "READY", f"firewall status {fw_status['Status']!r}"
    # GetAtt EndpointIds is "<AZ>:<vpce-id>" per entry.
    sync_ids = {f"{zone}:{s['Attachment']['EndpointId']}"
                for zone, s in fw_status["SyncStates"].items()}
    assert sync_ids == set(out["FirewallEndpointIds"].split(",")), (
        f"GetAtt EndpointIds {out['FirewallEndpointIds']!r}, sync states {sync_ids!r}"
    )

    policy = nfw.describe_firewall_policy(FirewallPolicyName=f"{name}-policy")
    got_policy = (policy["FirewallPolicyResponse"]["FirewallPolicyArn"],
                  {k: policy["FirewallPolicy"].get(k) for k in _POLICY},
                  _own_tags(policy["FirewallPolicyResponse"].get("Tags")))
    want_policy = (out["PolicyArn"], _POLICY,
                   {"sim2real": stack, "sim2real-nfw": f"{name}-policy"})
    assert got_policy == want_policy, f"policy {got_policy!r}, expected {want_policy!r}"

    logging = nfw.describe_logging_configuration(FirewallName=f"{name}-fw")
    assert (out["LoggingRef"], logging["FirewallArn"]) == (out["FirewallArn"],) * 2, (
        f"LoggingConfiguration Ref {out['LoggingRef']!r}, FirewallArn {logging['FirewallArn']!r}"
    )
    configs = logging["LoggingConfiguration"]["LogDestinationConfigs"]
    assert configs == [{"LogType": "FLOW", "LogDestinationType": "CloudWatchLogs",
                        "LogDestination": {"logGroup": log_group}}], f"logging {configs!r}"

    # Child first: an update dropping the LoggingConfiguration empties it on the same firewall.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(name, log_group, az, False))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"logging-removing update ended {status!r}"
    after = nfw.describe_logging_configuration(FirewallName=f"{name}-fw")
    left = after.get("LoggingConfiguration", {}).get("LogDestinationConfigs", [])
    assert (after["FirewallArn"], left) == (out["FirewallArn"], []), (
        f"after dropping the logging configuration the firewall reads {after!r}"
    )

    delete_stack(cf, stack_id)
    not_found = ("ResourceNotFoundException", _NOT_FOUND)
    expect_error(lambda: nfw.describe_firewall(FirewallName=f"{name}-fw"), *not_found)
    not_found_2 = ("ResourceNotFoundException", _NOT_FOUND)
    expect_error(
        lambda: nfw.describe_firewall_policy(FirewallPolicyName=f"{name}-policy"),
        *not_found_2,
    )
    not_found_3 = ("InvalidSubnetID.NotFound", f"The subnet ID '{out['SubnetId']}' does not exist")
    expect_error(lambda: ec2.describe_subnets(SubnetIds=[out["SubnetId"]]), *not_found_3)
    not_found_4 = ("InvalidVpcID.NotFound", f"The vpc ID '{vpc_id}' does not exist")
    expect_error(lambda: ec2.describe_vpcs(VpcIds=[vpc_id]), *not_found_4)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
