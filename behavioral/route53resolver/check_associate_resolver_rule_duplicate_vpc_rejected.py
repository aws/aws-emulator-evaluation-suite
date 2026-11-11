"""associate-resolver-rule-duplicate-vpc-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-resolver-rule-duplicate-vpc-rejected"
GROUP = "error-semantics"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateResolverRule for a rule and VPC already associated is refused with
    ResourceExistsException and leaves the single original association; after disassociating, the
    same association succeeds again.
    """
    r53r = ctx.client("route53resolver")
    ec2 = ctx.client("ec2")

    vpc_id = _get_usable_vpc(ec2, ctx=ctx)
    rule_id = _create_system_rule(ctx, r53r)

    # Positive control: first association succeeds.
    first = r53r.associate_resolver_rule(ResolverRuleId=rule_id, VPCId=vpc_id)["ResolverRuleAssociation"]
    assoc_id = first["Id"]
    ctx.on_cleanup(lambda: _safe_disassociate(r53r, rule_id, vpc_id))
    _poll_until(
        lambda: r53r.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id)["ResolverRuleAssociation"],
        lambda a: a["Status"] in ("COMPLETE", "OVERRIDDEN"),
        timeout_s=120,
        interval_s=3,
    )

    # Break exactly one thing: associate the same rule + VPC pair again.
    err = _reject_error(lambda: r53r.associate_resolver_rule(ResolverRuleId=rule_id, VPCId=vpc_id))
    assert err["Code"] == "ResourceExistsException", f"expected ResourceExistsException, got {err!r}"
    assert err["Message"] == (
        f'[RSLVR-00704] Resolver rule "{rule_id}" is already associated with VPC "{vpc_id}".'
    ), err

    # Effect absent: exactly one association exists between this rule and this VPC.
    assocs = r53r.list_resolver_rule_associations(
        Filters=[{"Name": "ResolverRuleId", "Values": [rule_id]}, {"Name": "VPCId", "Values": [vpc_id]}]
    )["ResolverRuleAssociations"]
    assert len(assocs) == 1, f"expected exactly 1 association, found {len(assocs)}"
    assert assocs[0]["Id"] == assoc_id, f"expected the untouched original {assoc_id!r}, found {assocs[0]['Id']!r}"

    # Restore: the blocking condition is the existing association, and removing it is
    # reversible, so this is a broken-then-restored negative -- the identical call succeeds
    # once the state that forbade it is gone.
    r53r.disassociate_resolver_rule(VPCId=vpc_id, ResolverRuleId=rule_id)
    gone_code = _poll_until(
        lambda: _error_code(
            lambda: r53r.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id)
        ),
        lambda c: c == "ResourceNotFoundException",
        timeout_s=120,
        interval_s=3,
    )
    assert gone_code == "ResourceNotFoundException", (
        f"expected the disassociated {assoc_id!r} to read back not-found, got {gone_code!r}"
    )

    second = r53r.associate_resolver_rule(ResolverRuleId=rule_id, VPCId=vpc_id)["ResolverRuleAssociation"]
    second_assoc_id = second["Id"]
    assert second_assoc_id != assoc_id, (
        f"expected a fresh association id after re-associating, got the stale {assoc_id!r} again"
    )
    _poll_until(
        lambda: r53r.get_resolver_rule_association(ResolverRuleAssociationId=second_assoc_id)["ResolverRuleAssociation"],
        lambda a: a["Status"] in ("COMPLETE", "OVERRIDDEN"),
        timeout_s=120,
        interval_s=3,
    )


def _reject_error(fn):
    """Call fn(); return the rejection's ``Error``. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


_SUCCEEDED = "<no error: the call succeeded>"


def _error_code(fn):
    """Call fn(); return the error code, or _SUCCEEDED (which no code equals). For polling toward
    an expected failure code, where success means 'not yet', not 'wrongly accepted'."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    return _SUCCEEDED


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _get_usable_vpc(ec2, *, ctx):
    # Use the check's own network VPC (ctx.network()); the check needs nothing from the VPC
    # beyond an id to associate the rule with, so it does not create or delete one.
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    assert vpcs, f"the run's shared network {ctx.network().vpc_id} is not visible"
    return vpcs[0]["VpcId"]


def _create_system_rule(ctx, r53r):
    # A SYSTEM rule is VPC-associable and needs neither a Resolver endpoint nor
    # TargetIps, keeping this check well inside its wall-clock budget while still
    # exercising the same ResolverRuleAssociation state machine as FORWARD/CONDITIONAL.
    resp = r53r.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-crr-"),
        Name=ctx.unique_name("sim2real-rule-")[:64],
        RuleType="SYSTEM",
        DomainName=f"{ctx.unique_name('sim2real-r53r-dupvpc-')}.example.internal.",
    )["ResolverRule"]
    rule_id = resp["Id"]
    ctx.on_cleanup(lambda: _safe_delete_rule(r53r, rule_id))
    _poll_until(
        lambda: r53r.get_resolver_rule(ResolverRuleId=rule_id)["ResolverRule"]["Status"],
        lambda s: s == "COMPLETE",
        timeout_s=60,
        interval_s=2,
    )
    return rule_id


def _safe_delete_rule(r53r, rule_id, timeout_s=180.0):
    """Delete the rule once its asynchronous disassociation has drained; gone is success."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            r53r.delete_resolver_rule(ResolverRuleId=rule_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(5)


def _safe_disassociate(r53r, rule_id, vpc_id):
    try:
        r53r.disassociate_resolver_rule(VPCId=vpc_id, ResolverRuleId=rule_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
