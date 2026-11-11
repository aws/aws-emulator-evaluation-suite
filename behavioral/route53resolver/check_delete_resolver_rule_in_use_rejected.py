"""delete-resolver-rule-in-use-rejected."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "delete-resolver-rule-in-use-rejected"
GROUP = 'overly-permissive'
SERVICES = ['route53resolver']

TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

_SUCCEEDED = "<no error: the call succeeded>"


def _err_code(fn):
    """Call fn(); return botocore Error.Code, or _SUCCEEDED (which no code equals)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return _SUCCEEDED


def _err(fn):
    """Call fn(); return (Error.Code, HTTP status, Error.Message), or (_SUCCEEDED, None, "")."""
    try:
        fn()
    except ClientError as exc:
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return exc.response.get("Error", {}).get("Code"), status, exc.response.get("Error", {}).get("Message") or ""
    return _SUCCEEDED, None, ""


def _poll(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_test_vpc(ctx):
    """Create a dedicated VPC the rule is associated with, registered for teardown. A SYSTEM rule
    needs no subnets or security group, and the check never borrows the default VPC."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.90.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": TAGS_KV + [
            {"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda v=vpc_id: _delete_net(ec2, "delete_vpc", VpcId=v))
    return vpc_id


_TEARDOWN_S = 300.0


def _delete_resolver_rule(r53, rule_id):
    """Teardown: delete the rule, retrying while a disassociation is still clearing; only
    ResourceNotFoundException (already gone) is tolerated, and a timeout raises."""
    deadline = time.monotonic() + _TEARDOWN_S
    while True:
        try:
            r53.delete_resolver_rule(ResolverRuleId=rule_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(5)


def _disassoc_resolver_rule(r53, rule_id, vpc_id):
    """Disassociate the rule from the VPC and wait until no association remains; only
    ResourceNotFoundException (association already gone) is tolerated, and a timeout raises."""
    try:
        r53.disassociate_resolver_rule(VPCId=vpc_id, ResolverRuleId=rule_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
    _poll(
        lambda: r53.list_resolver_rule_associations(
            Filters=[{"Name": "ResolverRuleId", "Values": [rule_id]}]
        )["ResolverRuleAssociations"],
        lambda assocs: not assocs,
        timeout_s=_TEARDOWN_S,
        interval_s=5,
        description=f"resolver rule {rule_id} has no VPC association left",
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResolverRule on a rule associated with a VPC raises ResourceInUseException and the
    rule stays COMPLETE, while an unused rule deletes cleanly; once disassociated, the identical
    delete succeeds and the rule is gone."""
    r53 = ctx.client("route53resolver")

    # positive control: an unused resolver rule deletes cleanly, so a later rejection can
    # only be attributed to the association, never to DeleteResolverRule being broken outright.
    unused_domain = f"{ctx.unique_name('sim2real-behav-zone-unused-')}.example.internal."
    unused_rule_id = r53.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-rr-unused-"),
        RuleType="SYSTEM",
        DomainName=unused_domain,
    )["ResolverRule"]["Id"]
    ctx.on_cleanup(lambda x=unused_rule_id: _delete_resolver_rule(r53, x))

    def unused_rule_status():
        return r53.get_resolver_rule(ResolverRuleId=unused_rule_id)["ResolverRule"]["Status"]

    _poll(unused_rule_status, lambda s: s == "COMPLETE", timeout_s=60, interval_s=2,
          description="unused rule reaches COMPLETE")
    r53.delete_resolver_rule(ResolverRuleId=unused_rule_id)
    unused_gone_code = _poll(
        lambda: _err_code(lambda: r53.get_resolver_rule(ResolverRuleId=unused_rule_id)),
        lambda c: c == "ResourceNotFoundException",
        timeout_s=120,
        interval_s=3,
        description="unused rule confirmed gone after delete",
    )
    assert unused_gone_code == "ResourceNotFoundException", (
        f"expected unused rule gone after delete, got {unused_gone_code!r}"
    )

    domain_name = f"{ctx.unique_name('sim2real-behav-zone-')}.example.internal."
    rule_name = ctx.unique_name("sim2real-behav-rr-")
    rule_id = r53.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=rule_name,
        RuleType="SYSTEM",
        DomainName=domain_name,
    )["ResolverRule"]["Id"]
    ctx.on_cleanup(lambda x=rule_id: _delete_resolver_rule(r53, x))
    def rule_status():
        return r53.get_resolver_rule(ResolverRuleId=rule_id)["ResolverRule"]["Status"]

    _poll(rule_status, lambda s: s == "COMPLETE", timeout_s=60, interval_s=2)

    vpc_id = _create_test_vpc(ctx)
    r53.associate_resolver_rule(
        ResolverRuleId=rule_id, VPCId=vpc_id, Name=ctx.unique_name("sim2real-behav-rra-")
    )
    ctx.on_cleanup(lambda rr=rule_id, v=vpc_id: _disassoc_resolver_rule(r53, rr, v))
    # An associated rule is in use and must not be deletable. Association
    # provisioning is asynchronous, so retry until the guard is observed rather
    # than blocking on the association reaching COMPLETE first.
    def delete_attempt():
        return _err(lambda: r53.delete_resolver_rule(ResolverRuleId=rule_id))

    code, status, message = _poll(
        delete_attempt,
        lambda r: r[0] == "ResourceInUseException",
        timeout_s=90,
        interval_s=5,
        description="DeleteResolverRule rejected with ResourceInUseException",
    )
    assert code == "ResourceInUseException", f"expected ResourceInUseException, got {code}"
    assert status == 400, f"expected HTTP 400 for the in-use delete, got {status!r}"
    expected_message = "[RSLVR-00702] Please disassociate this resolver rule from VPC first before deleting."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # effect absent: the rule must still exist, unaffected by the rejected delete attempt.
    still_there = r53.get_resolver_rule(ResolverRuleId=rule_id)["ResolverRule"]
    assert still_there["Status"] == "COMPLETE", (
        f"expected rule to remain COMPLETE after rejected delete, got {still_there['Status']!r}"
    )

    # restore: once disassociated, the identical delete call now succeeds.
    _disassoc_resolver_rule(r53, rule_id, vpc_id)
    # Retry only while the disassociation is still propagating (still in use).
    restore = _poll(
        delete_attempt,
        lambda r: r[0] != "ResourceInUseException",
        timeout_s=120,
        interval_s=5,
        description="DeleteResolverRule no longer refused as in use once the association is gone",
    )
    # The poll stops at the first answer that is not ResourceInUseException, so no earlier attempt
    # of it can have removed the rule: the identical delete must succeed.
    assert restore[0] == _SUCCEEDED, (
        f"expected the identical delete to succeed after disassociation, got {restore!r}"
    )
    removed_code = _poll(
        lambda: _err_code(lambda: r53.get_resolver_rule(ResolverRuleId=rule_id)),
        lambda c: c == "ResourceNotFoundException",
        timeout_s=120,
        interval_s=3,
        description="GetResolverRule confirms the rule gone after restore+delete",
    )
    assert removed_code == "ResourceNotFoundException", (
        f"expected rule gone after restore+delete, got {removed_code!r}"
    )
    listed = [
        r["Id"]
        for page in r53.get_paginator("list_resolver_rules").paginate(
            Filters=[{"Name": "Name", "Values": [rule_name]}]
        )
        for r in page.get("ResolverRules", [])
    ]
    assert rule_id not in listed, f"deleted rule {rule_id!r} is still listed by ListResolverRules"
    code, status, message = _err(
        lambda: r53.update_resolver_rule(ResolverRuleId=rule_id, Config={"Name": "sim2real-dead"})
    )
    assert code == "ResourceNotFoundException", f"UpdateResolverRule after delete: got {code!r}"
    assert status == 400, f"UpdateResolverRule after delete: expected HTTP 400, got {status!r}"
    expected_message = f'[RSLVR-00703] Resolver rule with ID "{rule_id}" does not exist.'
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


# EC2 network teardown waits (bounded) for ENIs to leave before it deletes, retries
# DependencyViolation inside the same window, and raises a final failure naming the ENIs; EC2's
# own *.NotFound means already gone. Every other error propagates.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and time.monotonic() < deadline:
        time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith(".NotFound"):
                return None
            if code != "DependencyViolation":
                raise
            if time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        time.sleep(10)


def _net_enis(client, flt):
    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
