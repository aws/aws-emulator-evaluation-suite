"""security-group-rules-quota-is-enforced-per-direction-at-the-accounts-own-limit-rejected."""
from __future__ import annotations

import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "security-group-rules-quota-is-enforced-per-direction-at-the-accounts-own-limit-rejected"
GROUP = "security-group"
SERVICES = ["ec2"]

_VPC_CIDR = "10.78.0.0/16"
_QUOTA_SERVICE = "vpc"
_QUOTA_NAME_FRAGMENT = "rules per security group"
# The published ceiling on (rules per security group) x (security groups per network interface);
# only a sanity bound on the loop, never the expected value.
_RULE_CEILING = 1000
_PORT = 4433
_LIMIT_MESSAGE = "The maximum number of rules per security group has been reached."
_IPV6_PROBE = "2001:db8:5e2:1::/64"  # RFC 3849 documentation prefix
_GONE_CODES = ("InvalidVpcID.NotFound", "InvalidGroup.NotFound", "InvalidPermission.NotFound")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """IPv4 inbound rules fill to the account's Service Quotas limit and one more is refused
    (RulesPerSecurityGroupLimitExceeded, no effect); IPv6 inbound and IPv4 outbound rules are
    still accepted, and revoking one inbound rule lets the refused call succeed.

    Reference: https://docs.aws.amazon.com/vpc/latest/userguide/amazon-vpc-limits.html
    """
    ec2 = ctx.client("ec2")
    quotas = ctx.client("service-quotas")
    st: dict = {"sgs": []}
    try:
        limit = _reported_limit(quotas)
        _build(ctx, ec2, st)
        _legs(ec2, st, limit)
    finally:
        _teardown(ec2, st)


def _legs(ec2, st, limit) -> None:
    group_id = st["group"]

    # A new group holds one rule, the default IPv4 egress allow-all; counts are relative to it.
    assert _count(ec2, group_id, egress=False) == 0, (
        f"a freshly created security group must hold zero INBOUND rules, "
        f"DescribeSecurityGroupRules reports {_rules(ec2, group_id, egress=False)!r}"
    )
    baseline_egress = _count(ec2, group_id, egress=True)
    assert baseline_egress == 1, (
        f"a freshly created security group must hold exactly one default egress rule; it holds "
        f"{baseline_egress}: {_rules(ec2, group_id, egress=True)!r}"
    )

    cidrs = [_probe_cidr(i) for i in range(limit)]
    assert len(set(cidrs)) == limit, (
        f"the probe CIDRs must be distinct or they would collapse into fewer rules: generated "
        f"{len(set(cidrs))} distinct out of {limit}"
    )
    # Fill to limit-1 in bulk, then reach the limit with a single-rule call, so the refused call
    # below differs from an accepted one by exactly one rule.
    if limit > 1:
        _authorize(ec2, group_id, cidrs[:-1])
    _authorize(ec2, group_id, cidrs[-1:])
    filled = _count(ec2, group_id, egress=False)
    assert filled == limit, (
        f"the account reports a limit of {limit} inbound rules per security group, so exactly "
        f"{limit} must be accepted; DescribeSecurityGroupRules counts {filled}"
    )

    overflow = _probe_cidr(limit)
    err = _client_error(lambda: _authorize(ec2, group_id, [overflow]))
    assert err.get("Code") == "RulesPerSecurityGroupLimitExceeded", (
        f"inbound rule number {limit + 1} must be refused with RulesPerSecurityGroupLimitExceeded; got "
        f"{err.get('Code')!r} ({err.get('Message')!r})"
    )
    assert err.get("Message") == _LIMIT_MESSAGE, f"unexpected message: {err.get('Message')!r}"

    after = _rules(ec2, group_id, egress=False)
    assert len(after) == limit, (
        f"a refused authorize must add nothing: expected {limit} inbound rules still, got "
        f"{len(after)}"
    )
    assert overflow not in {r.get("CidrIpv4") for r in after}, (
        f"the refused CIDR {overflow!r} must not appear among the group's rules"
    )

    # The quota is counted separately per direction and per address family.
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": _PORT, "ToPort": _PORT,
                        "Ipv6Ranges": [{"CidrIpv6": _IPV6_PROBE,
                                        "Description": "sim2real ipv6 bucket control"}]}],
    )
    v6 = [r for r in _rules(ec2, group_id, egress=False) if r.get("CidrIpv6")]
    assert len(v6) == 1, (
        f"the quota is enforced separately for IPv4 and IPv6, so an IPv6 inbound rule must be "
        f"accepted while the IPv4 inbound bucket is full; the group holds {len(v6)} IPv6 inbound "
        f"rules: {v6!r}"
    )
    assert v6[0]["CidrIpv6"] == _IPV6_PROBE, (
        f"expected the accepted IPv6 rule to carry {_IPV6_PROBE!r}, got {v6[0]!r}"
    )
    ec2.authorize_security_group_egress(
        GroupId=group_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": _PORT, "ToPort": _PORT,
                        "IpRanges": [{"CidrIp": _probe_cidr(0),
                                      "Description": "sim2real egress bucket control"}]}],
    )
    egress_now = _count(ec2, group_id, egress=True)
    assert egress_now == baseline_egress + 1, (
        f"the quota is enforced separately for inbound and outbound, so an OUTBOUND rule must be "
        f"accepted while the inbound bucket is full; the egress count went "
        f"{baseline_egress} -> {egress_now}"
    )
    err_again = _client_error(lambda: _authorize(ec2, group_id, [overflow]))
    assert err_again.get("Code") == "RulesPerSecurityGroupLimitExceeded", (
        f"the IPv4 inbound bucket must still be full after the other buckets were written; got "
        f"{err_again.get('Code')!r}"
    )
    assert err_again.get("Message") == _LIMIT_MESSAGE, (
        f"unexpected message: {err_again.get('Message')!r}"
    )

    ec2.revoke_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": _PORT, "ToPort": _PORT,
                        "IpRanges": [{"CidrIp": cidrs[0]}]}],
    )
    freed = _count(ec2, group_id, egress=False)
    assert freed == limit, (
        f"revoking one IPv4 inbound rule must leave {limit} inbound rules (the {limit - 1} "
        f"remaining IPv4 plus the one IPv6 control), got {freed}"
    )
    _authorize(ec2, group_id, [overflow])
    final = _rules(ec2, group_id, egress=False)
    assert overflow in {r.get("CidrIpv4") for r in final}, (
        f"after freeing a slot the previously refused CIDR {overflow!r} must be present; the group "
        f"holds {sorted(r.get('CidrIpv4') for r in final if r.get('CidrIpv4'))!r}"
    )
    assert cidrs[0] not in {r.get("CidrIpv4") for r in final}, (
        f"the revoked CIDR {cidrs[0]!r} must NOT have come back"
    )
    assert len([r for r in final if r.get("CidrIpv4")]) == limit, (
        f"the IPv4 inbound bucket must be full again at the account's reported limit {limit}, got "
        f"{len([r for r in final if r.get('CidrIpv4')])}"
    )


def _reported_limit(quotas) -> int:
    """The account's rules-per-security-group quota, read at run time because it is adjustable."""
    seen = {}
    for page in quotas.get_paginator("list_service_quotas").paginate(
            ServiceCode=_QUOTA_SERVICE):
        for quota in page["Quotas"]:
            seen[quota["QuotaName"]] = quota
    matches = [q for name, q in seen.items() if _QUOTA_NAME_FRAGMENT in name.lower()]
    assert len(matches) == 1, (
        f"service-quotas must report exactly one {_QUOTA_SERVICE!r} quota whose name contains "
        f"{_QUOTA_NAME_FRAGMENT!r}; it reported {[q['QuotaName'] for q in matches]!r} out of "
        f"{sorted(seen)!r}"
    )
    quota = matches[0]
    limit = int(quota["Value"])
    assert quota["Adjustable"] is True, (
        f"this quota is documented as adjustable, which is exactly why it is read rather than "
        f"pinned; service-quotas reports {quota!r}"
    )
    direct = quotas.get_service_quota(
        ServiceCode=_QUOTA_SERVICE, QuotaCode=quota["QuotaCode"])["Quota"]
    assert int(direct["Value"]) == limit, (
        f"GetServiceQuota and ListServiceQuotas must agree on {quota['QuotaCode']}: "
        f"{int(direct['Value'])} vs {limit}"
    )
    assert 1 <= limit <= _RULE_CEILING, (
        f"the reported rules-per-security-group quota {limit} is outside the published range "
        f"[1, {_RULE_CEILING}]; refusing to fill a bucket of that size: {quota!r}"
    )
    return limit


def _build(ctx, ec2, st) -> None:
    """A VPC and security group of this check's own, so the filled quota touches nothing else."""
    name = ctx.unique_name("sim2real-b1sgq-")
    st["name"] = name

    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_for(name)}],
    )["Vpc"]["VpcId"]
    st["vpc"] = vpc_id
    ctx.on_cleanup(lambda: _delete_vpc_quiet(ec2, vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    group_id = ec2.create_security_group(
        GroupName=name + "-sg", VpcId=vpc_id,
        Description="sim2real rules-per-security-group quota check",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(name)}],
    )["GroupId"]
    st["sgs"].append(group_id)
    st["group"] = group_id


def _assert_absent(listed):
    """Teardown step: a deleted resource must no longer be listed."""
    if listed:
        raise AssertionError(f"still describable after its delete: {listed!r}")


def _teardown(ec2, st) -> None:
    steps: list = []

    def _step(label, fn):
        steps.append((label, fn))

    for sg in st.get("sgs", []):
        _step(f"sg {sg}", lambda s=sg: _retry_dependency(
            lambda: ec2.delete_security_group(GroupId=s)))
    if st.get("vpc"):
        _step("vpc", lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=st["vpc"])))
        _step("vpc-gone", lambda: _assert_absent(ec2.describe_vpcs(VpcIds=[st["vpc"]])["Vpcs"]))
    left: list[str] = []
    for label, fn in steps:
        try:
            fn()
        except ClientError as exc:
            if _code(exc) not in _GONE_CODES:
                left.append(f"{label}: {_code(exc)}")
        except Exception as exc:  # noqa: BLE001 — every step runs; the failures are raised together
            left.append(f"{label}: {exc!r}")
    if left:
        found = sys.exc_info()[1]
        raise AssertionError(
            (f"{found!r}; " if found else "")
            + f"teardown could not remove everything the check created: {left!r}"
        )


def _delete_vpc_quiet(ec2, vpc_id):
    """Safety-net cleanup: the in-band teardown normally deletes the VPC first."""
    try:
        ec2.delete_vpc(VpcId=vpc_id)
    except ClientError as exc:
        if _code(exc) != "InvalidVpcID.NotFound":
            raise


def _tags_for(name):
    return [{"Key": "sim2real", "Value": "1"}, {"Key": "Name", "Value": name}]


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _client_error(fn):
    """Call fn() and return its botocore Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}"
    )


def _retry_dependency(fn, attempts=12, delay=10.0):
    for attempt in range(attempts):
        try:
            fn()
            return
        except ClientError as exc:
            if _code(exc) in _GONE_CODES:
                return
            if _code(exc) not in ("DependencyViolation", "RequestLimitExceeded") \
                    or attempt == attempts - 1:
                raise
            time.sleep(delay)


def _probe_cidr(index: int) -> str:
    """A distinct /32 from 198.18.0.0/15, the non-routable RFC 2544 benchmarking range."""
    assert 0 <= index <= _RULE_CEILING, f"probe index {index} out of range"
    return f"198.18.{index // 254}.{index % 254 + 1}/32"


def _authorize(ec2, group_id, cidrs):
    """One AuthorizeSecurityGroupIngress carrying every CIDR — one rule per CIDR."""
    assert cidrs, "refusing to issue an authorize with no CIDRs: it would assert nothing"
    return ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": _PORT, "ToPort": _PORT,
            "IpRanges": [{"CidrIp": c, "Description": "sim2real sg quota probe"} for c in cidrs],
        }],
    )


def _rules(ec2, group_id, *, egress):
    """Every rule on the group in one direction, read through DescribeSecurityGroupRules."""
    out = []
    for page in ec2.get_paginator("describe_security_group_rules").paginate(
            Filters=[{"Name": "group-id", "Values": [group_id]}]):
        for rule in page["SecurityGroupRules"]:
            if rule["IsEgress"] is egress:
                out.append(rule)
    return out


def _count(ec2, group_id, *, egress):
    return len(_rules(ec2, group_id, egress=egress))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
