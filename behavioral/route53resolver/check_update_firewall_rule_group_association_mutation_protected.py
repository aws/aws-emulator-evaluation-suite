"""update-firewall-rule-group-association-mutation-protected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-firewall-rule-group-association-mutation-protected"
GROUP = 'firewall-rule-group-association'
SERVICES = ['route53resolver']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateFirewallRuleGroupAssociation MUST fail to change Priority when MutationProtection is
    ENABLED, and the identical Priority change MUST succeed once MutationProtection is disabled
    again."""
    r53r = ctx.client("route53resolver")
    vpc_id = _create_vpc(ctx, ctx.client("ec2"), "10.95.0.0/16")

    group_id = r53r.create_firewall_rule_group(
        CreatorRequestId=_creator_request_id(ctx),
        Name=ctx.unique_name("sim2real-behav-frg-"),
        Tags=_tags(),
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda: _delete_group_retrying(r53r, group_id))

    assoc = r53r.associate_firewall_rule_group(
        CreatorRequestId=_creator_request_id(ctx),
        FirewallRuleGroupId=group_id,
        VpcId=vpc_id,
        Priority=201,
        Name=ctx.unique_name("sim2real-behav-assoc-"),
        MutationProtection="DISABLED",
        Tags=_tags(),
    )["FirewallRuleGroupAssociation"]
    assoc_id = assoc["Id"]
    # MutationProtection blocks Disassociate too, so teardown must clear it first.
    ctx.on_cleanup(lambda: _disassociate_protected(r53r, assoc_id))
    assert assoc["MutationProtection"] == "DISABLED", assoc

    def probe():
        return r53r.get_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=assoc_id
        )["FirewallRuleGroupAssociation"]

    _poll_until(probe, lambda r: r["Status"] == "COMPLETE", timeout_s=180, interval_s=3)

    # Positive control: an unprotected association takes a Priority change cleanly.
    r53r.update_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id, Priority=202)
    control = _poll_until(
        probe, lambda r: r["Status"] == "COMPLETE" and r["Priority"] == 202, timeout_s=180, interval_s=3
    )
    assert control["Priority"] == 202, control

    # Break exactly one thing: turn MutationProtection on.
    r53r.update_firewall_rule_group_association(
        FirewallRuleGroupAssociationId=assoc_id, MutationProtection="ENABLED"
    )
    protected = _poll_until(
        probe,
        lambda r: r["Status"] == "COMPLETE" and r["MutationProtection"] == "ENABLED",
        timeout_s=180,
        interval_s=2,
    )
    assert protected["MutationProtection"] == "ENABLED", protected

    refusal = _error(
        lambda: r53r.update_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=assoc_id, Priority=999
        )
    )
    expected = (
        "ValidationException",
        "[RSLVR-02307] The DNS Firewall rule group association is under mutation protection. "
        "Remove the mutation protection and try again.",
    )
    assert refusal == expected, f"expected {expected!r}, got {refusal!r}"

    # Effect absent: the protected association is untouched.
    after = probe()
    assert after["Priority"] == 202, after
    assert after["MutationProtection"] == "ENABLED", after

    # Restore: disable protection, then the identical Priority change now succeeds.
    r53r.update_firewall_rule_group_association(
        FirewallRuleGroupAssociationId=assoc_id, MutationProtection="DISABLED"
    )
    _poll_until(
        probe,
        lambda r: r["Status"] == "COMPLETE" and r["MutationProtection"] == "DISABLED",
        timeout_s=180,
        interval_s=2,
    )
    r53r.update_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id, Priority=999)
    restored = _poll_until(
        probe, lambda r: r["Status"] == "COMPLETE" and r["Priority"] == 999, timeout_s=180, interval_s=3
    )
    assert restored["Priority"] == 999, restored


# ===== helpers =====

def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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


def _tags() -> list[dict]:
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


def _creator_request_id(ctx) -> str:
    """A fresh CreatorRequestId for idempotency-token style params."""
    return ctx.unique_name("sim2real-behav-crid-")


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


def _delete_group_retrying(r53r, group_id: str, timeout_s: float = 180.0, interval_s: float = 2.0) -> None:
    """DeleteFirewallRuleGroup conflicts while the association it just left is still winding
    down (Disassociate is async): retry ConflictException to the deadline, raise anything else."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            r53r.delete_firewall_rule_group(FirewallRuleGroupId=group_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _disassociate_protected(r53r, assoc_id: str) -> None:
    _swallow(
        lambda: r53r.update_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=assoc_id, MutationProtection="DISABLED"
        )
    )
    _swallow(
        lambda: r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s. Last result: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
