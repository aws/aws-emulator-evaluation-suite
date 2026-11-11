"""deploy-firewall-rule-group-cfn-association-active."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "deploy-firewall-rule-group-cfn-association-active"
GROUP = "state-machine"
SERVICES = ["route53resolver"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  DomainListName:
    Type: String
  RuleGroupName:
    Type: String
Resources:
  DomainList:
    Type: AWS::Route53Resolver::FirewallDomainList
    Properties:
      Name: !Ref DomainListName
      Domains:
        - cfn-blocked-example.test.
  RuleGroup:
    Type: AWS::Route53Resolver::FirewallRuleGroup
    Properties:
      Name: !Ref RuleGroupName
      FirewallRules:
        - FirewallDomainListId: !Ref DomainList
          Priority: 100
          Action: BLOCK
          BlockResponse: NXDOMAIN
Outputs:
  RuleGroupId:
    Value: !Ref RuleGroup
  DomainListId:
    Value: !Ref DomainList
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed rule group associated with a VPC reaches COMPLETE, is listed and
    updatable; after disassociation it is removed and a further update on its id raises
    ResourceNotFoundException."""
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    r53r = ctx.client("route53resolver")
    trace_root = _traced(r53r)

    vpc_id = _create_vpc(ctx, ec2)

    stack_name = ctx.unique_name("sim2real-r53r-fwcfn-")
    outputs = _deploy_cfn(
        ctx,
        cfn,
        stack_name,
        _TEMPLATE,
        [
            {"ParameterKey": "DomainListName", "ParameterValue": ctx.unique_name("sim2real-fwdomains-")[:64]},
            {"ParameterKey": "RuleGroupName", "ParameterValue": ctx.unique_name("sim2real-fwgroup-")[:64]},
        ],
    )
    group_id = outputs["RuleGroupId"]

    rules = _poll_until(
        lambda: r53r.list_firewall_rules(FirewallRuleGroupId=group_id)["FirewallRules"],
        lambda rs: len(rs) == 1,
        timeout_s=120,
        interval_s=1,
        ctx=ctx,
    )
    assert rules[0]["Action"] == "BLOCK"

    assoc_id = r53r.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-afrg-"),
        FirewallRuleGroupId=group_id,
        VpcId=vpc_id,
        Priority=101,
        Name=ctx.unique_name("sim2real-fwassoc-")[:64],
        MutationProtection="DISABLED",
    )["FirewallRuleGroupAssociation"]["Id"]
    ctx.on_cleanup(lambda: _safe_disassociate(r53r, assoc_id))

    active = _poll_until(
        lambda: r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)[
            "FirewallRuleGroupAssociation"
        ],
        lambda a: a["Status"] in ("COMPLETE", "DELETING"),
        timeout_s=300,
        interval_s=1,
        ctx=ctx,
    )
    assert active["Status"] == "COMPLETE"

    # Prove it is usable by later calls, not just present: it shows up in the list for
    # this VPC, and it can be mutated.
    listed = r53r.list_firewall_rule_group_associations(VpcId=vpc_id)["FirewallRuleGroupAssociations"]
    assert any(a["Id"] == assoc_id for a in listed)

    r53r.update_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id, Priority=150)
    updated = _poll_until(
        lambda: r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)[
            "FirewallRuleGroupAssociation"
        ],
        lambda a: a["Status"] == "COMPLETE" and a["Priority"] == 150,
        timeout_s=300,
        interval_s=1,
        ctx=ctx,
    )
    assert updated["Priority"] == 150

    # Teardown is asserted, not just performed: disassociating must make the
    # association genuinely gone (independent read) and dead to a further mutation.
    r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
    _poll_until_removed(r53r, assoc_id, timeout_s=300, interval_s=1, ctx=ctx)

    dead_code, dead_message = _client_error(
        lambda: r53r.update_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id, Priority=200)
    )
    assert dead_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {dead_code!r}"
    expected = (
        f'[RSLVR-02025] Can’t find the resource with ID "{assoc_id}". Trace Id: "{trace_root}"'
    )
    assert dead_message == expected, f"expected message {expected!r}, got {dead_message!r}"


def _client_error(fn):
    """Call fn(), which AWS refuses; return the (code, message) of its ClientError."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call succeeded; expected AWS to refuse it with a ClientError")


def _traced(client):
    """Send one caller-chosen X-Ray trace id on every call of client; return its Root.

    Route 53 Resolver ends a DNS Firewall refusal message with the caller's trace Root,
    so a fixed Root makes the whole message exact.
    """
    root = f"1-{int(time.time()):08x}-{uuid.uuid4().hex[:24]}"
    header = f"Root={root};Sampled=0"

    def _add_header(request, **_):
        request.headers["X-Amzn-Trace-Id"] = header

    client.meta.events.register("before-sign.route53resolver.*", _add_header)
    return root


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until_removed(r53r, assoc_id, *, ctx, timeout_s=120.0, interval_s=3.0):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"association {assoc_id} removal: the run budget ended first; not graded")
    raise AssertionError(f"association {assoc_id} was not removed within {timeout_s:.0f}s")

def _poll_until(probe, predicate, *, ctx, timeout_s=60.0, interval_s=2.0):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError("condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s:.0f}s, last={last!r}")


def _create_vpc(ctx, ec2):
    name = ctx.unique_name("sim2real-r53r-vpc-")
    resp = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    vpc_id = resp["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return vpc_id


def _deploy_cfn(ctx, cfn, stack_name, template_body, parameters):
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=parameters,
        OnFailure="DELETE",
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    attempts = max(1, int(_budget_s(ctx, 600) / 2))
    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": attempts}
        )
    except WaiterError:
        if _budget_spent(ctx):
            raise TimeoutError(f"stack {stack_name} CREATE_COMPLETE: the run budget ended first; not graded")
        raise
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _delete_stack(cfn, stack_name, attempts=3):
    # A DNS Firewall resource can refuse its delete for a short while after a
    # disassociation, which leaves the stack DELETE_FAILED; deleting again finishes it.
    for attempt in range(1, attempts + 1):
        try:
            cfn.delete_stack(StackName=stack_name)
            cfn.get_waiter("stack_delete_complete").wait(
                StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
            )
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "ValidationError":
                return
            raise
        except WaiterError:
            if attempt == attempts:
                raise


def _safe_disassociate(r53r, assoc_id, timeout_s=600.0, interval_s=2.0):
    # Wait out an in-flight create or update, disassociate, then wait until the
    # association is gone so the stack delete that follows finds the rule group free.
    deadline = time.monotonic() + timeout_s
    requested = False
    while time.monotonic() < deadline:
        try:
            status = r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)[
                "FirewallRuleGroupAssociation"
            ]["Status"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if status == "COMPLETE" and not requested:
            try:
                r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
                requested = True
            except ClientError as e:
                if e.response["Error"]["Code"] == "ResourceNotFoundException":
                    return
                if e.response["Error"]["Code"] not in ("ConflictException", "ValidationException"):
                    raise
        time.sleep(interval_s)
    raise AssertionError(f"association {assoc_id} was not removed within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
