"""deploy-vpc-configs-cfn-reset-on-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-vpc-configs-cfn-reset-on-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "route53resolver"]

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


# ---- Check-specific: the template, then run(). ----

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  VpcId:
    Type: String
Resources:
  FirewallConfig:
    Type: AWS::Route53Resolver::FirewallConfig
    Properties:
      ResourceId: !Ref VpcId
      FirewallFailOpen: ENABLED
  ResolverConfig:
    Type: AWS::Route53Resolver::ResolverConfig
    Properties:
      ResourceId: !Ref VpcId
      AutodefinedReverseFlag: DISABLE
  ResolverDnssecConfig:
    Type: AWS::Route53Resolver::ResolverDNSSECConfig
    Properties:
      ResourceId: !Ref VpcId
Outputs:
  FirewallConfigArn:
    Value: !Ref FirewallConfig
  FirewallConfigId:
    Value: !GetAtt FirewallConfig.Id
  FirewallConfigOwnerId:
    Value: !GetAtt FirewallConfig.OwnerId
  ResolverConfigResourceId:
    Value: !Ref ResolverConfig
  ResolverConfigId:
    Value: !GetAtt ResolverConfig.Id
  ResolverConfigAutodefinedReverse:
    Value: !GetAtt ResolverConfig.AutodefinedReverse
  DnssecConfigId:
    Value: !Ref ResolverDnssecConfig
  DnssecConfigOwnerId:
    Value: !GetAtt ResolverDnssecConfig.OwnerId
  DnssecConfigValidationStatus:
    Value: !GetAtt ResolverDnssecConfig.ValidationStatus
"""


def _poll_until(probe, want, what, *, timeout_s=240.0, interval_s=5.0):
    """Poll ``probe()`` until it returns ``want``; raise naming the last value on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        got = probe()
        if got == want:
            return got
        if time.monotonic() > deadline:
            raise AssertionError(
                f"{what} still reads {got!r} after {timeout_s:.0f} s, expected {want!r}"
            )
        time.sleep(interval_s)


def _create_vpc(ctx, ec2):
    """A fresh tagged VPC; its resolver configs start at the account defaults."""
    name = ctx.unique_name("sim2real-r53r-vpccfg-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name},
                                                            {"Key": "sim2real", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    return vpc_id


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only the resource's own
    not_found codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A stack's FirewallConfig, ResolverConfig and ResolverDNSSECConfig each take effect on the
    VPC they target (fail-open, reverse lookup off, DNSSEC validation on) with Ref and GetAtt
    matching the live values, and deleting the stack restores each setting to its pre-deploy value.
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    r53r = ctx.client("route53resolver")
    vpc_id = _create_vpc(ctx, ec2)

    def firewall_open():
        return r53r.get_firewall_config(ResourceId=vpc_id)["FirewallConfig"]["FirewallFailOpen"]

    def reverse():
        return r53r.get_resolver_config(ResourceId=vpc_id)["ResolverConfig"]["AutodefinedReverse"]

    def dnssec():
        return r53r.get_resolver_dnssec_config(
            ResourceId=vpc_id)["ResolverDNSSECConfig"]["ValidationStatus"]

    before = (firewall_open(), reverse(), dnssec())

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-r53r-vpccfg-"), _TEMPLATE,
                            Parameters=[{"ParameterKey": "VpcId", "ParameterValue": vpc_id}])
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]

    firewall = r53r.get_firewall_config(ResourceId=vpc_id)["FirewallConfig"]
    want_arn = f"arn:{partition}:route53resolver:{ctx.region}:{ctx.account}:firewall-config/{vpc_id}"
    got = (outputs["FirewallConfigArn"], outputs["FirewallConfigId"],
           outputs["FirewallConfigOwnerId"], firewall["ResourceId"], firewall["FirewallFailOpen"])
    want = (want_arn, firewall["Id"], firewall["OwnerId"], vpc_id, "ENABLED")
    assert got == want, f"FirewallConfig (Ref, Id, OwnerId, ResourceId, FailOpen) {got!r}"

    resolver_cfg = r53r.get_resolver_config(ResourceId=vpc_id)["ResolverConfig"]
    got = (outputs["ResolverConfigResourceId"], outputs["ResolverConfigId"],
           outputs["ResolverConfigAutodefinedReverse"], resolver_cfg["ResourceId"],
           resolver_cfg["AutodefinedReverse"])
    want = (vpc_id, resolver_cfg["Id"], resolver_cfg["AutodefinedReverse"], vpc_id, "DISABLED")
    assert got == want, f"ResolverConfig (Ref, Id, GetAtt, ResourceId, live) {got!r}"

    dnssec_cfg = r53r.get_resolver_dnssec_config(ResourceId=vpc_id)["ResolverDNSSECConfig"]
    got = (outputs["DnssecConfigId"], outputs["DnssecConfigOwnerId"], dnssec_cfg["ResourceId"])
    want = (dnssec_cfg["Id"], dnssec_cfg["OwnerId"], vpc_id)
    assert got == want, f"ResolverDNSSECConfig (Ref, OwnerId, ResourceId) {got!r}"
    # GetAtt ValidationStatus is captured at stack completion, so the transition may still run.
    captured = outputs["DnssecConfigValidationStatus"]
    assert captured in {"ENABLING", "ENABLED"}, (
        f"GetAtt ResolverDNSSECConfig.ValidationStatus is {captured!r}, expected ENABLING or ENABLED"
    )
    # The DNSSEC config's existence is the setting: validation itself reaches ENABLED.
    _poll_until(dnssec, "ENABLED", "DNSSEC ValidationStatus")

    delete_stack(cfn, stack_id)
    after = (_poll_until(firewall_open, before[0], "FirewallFailOpen after the delete"),
             _poll_until(reverse, before[1], "AutodefinedReverse after the delete"),
             _poll_until(dnssec, before[2], "DNSSEC ValidationStatus after the delete"))
    assert after == before, (
        f"(FirewallFailOpen, AutodefinedReverse, ValidationStatus) after the delete {after!r}, "
        f"before the deploy {before!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
