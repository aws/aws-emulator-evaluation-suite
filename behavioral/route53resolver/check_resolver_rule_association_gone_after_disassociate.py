"""resolver-rule-association-gone-after-disassociate."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resolver-rule-association-gone-after-disassociate"
GROUP = "state-machine"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DisassociateResolverRule completes, GetResolverRuleAssociation for that
    VPC/rule pair returns ResourceNotFoundException rather than a stale COMPLETE record --
    the association is actually removed from the resolver's state, not merely marked."""
    ec2 = ctx.client("ec2")
    r53r = ctx.client("route53resolver")

    vpc_id = _create_vpc(ctx, ec2, "10.93.0.0/16")

    # RuleType SYSTEM needs neither TargetIps nor a ResolverEndpointId, so this exercises the
    # association state machine without provisioning VPC subnets/security-group/endpoint.
    rule_id = r53r.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-ruleassoc-rule-req-"),
        Name=ctx.unique_name("sim2real-ruleassoc-rule-")[:64],
        RuleType="SYSTEM",
        DomainName="apex.sim2real-ruleassoc.test.",
    )["ResolverRule"]["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: r53r.delete_resolver_rule(ResolverRuleId=rule_id)))

    assoc_id = r53r.associate_resolver_rule(ResolverRuleId=rule_id, VPCId=vpc_id)[
        "ResolverRuleAssociation"
    ]["Id"]

    status = _poll_until(
        lambda: r53r.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id)[
            "ResolverRuleAssociation"
        ]["Status"],
        lambda s: s in ("COMPLETE", "FAILED", "OVERRIDDEN"),
        timeout_s=120,
        interval_s=3,
    )
    assert status == "COMPLETE", f"association reached {status}, not COMPLETE"

    mid_flow = r53r.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id)[
        "ResolverRuleAssociation"
    ]
    assert mid_flow["ResolverRuleId"] == rule_id, (
        f"expected ResolverRuleId {rule_id!r}, got {mid_flow['ResolverRuleId']!r}"
    )
    assert mid_flow["VPCId"] == vpc_id, (
        f"expected VPCId {vpc_id!r}, got {mid_flow['VPCId']!r}"
    )

    r53r.disassociate_resolver_rule(VPCId=vpc_id, ResolverRuleId=rule_id)
    _poll_until(
        lambda: _absent(
            lambda: r53r.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id)
        ),
        lambda gone: gone,
        timeout_s=180,
        interval_s=3,
    )
    gone = _error(lambda: r53r.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id))
    expected = (
        "ResourceNotFoundException",
        f'ResolverRuleAssociation "{assoc_id}" does not Exist.',
    )
    assert gone == expected, f"expected {expected!r} after disassociate, got {gone!r}"


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    return value


_TRACE_ID = ' Trace Id: "'


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises, with the
    per-request X-Ray trace id suffix removed. A call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        message = err.get("Message", "")
        head, sep, _ = message.rpartition(_TRACE_ID)
        return err.get("Code"), (head if sep and message.endswith('"') else message)
    raise AssertionError(f"expected a ClientError, the call succeeded and returned {result!r}")


def _absent(fn) -> bool:
    """True once fn() raises ResourceNotFoundException, False while it still succeeds."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return True
        raise
    return False


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_vpc(ctx, ec2, cidr: str) -> str:
    """A fresh VPC owned by this check, deleted at teardown."""
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc(ec2, vpc_id))
    return vpc_id


def _delete_vpc(ec2, vpc_id: str, *, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    """Retry while an association the check just removed still holds the VPC."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_vpc(VpcId=vpc_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "InvalidVpcID.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
