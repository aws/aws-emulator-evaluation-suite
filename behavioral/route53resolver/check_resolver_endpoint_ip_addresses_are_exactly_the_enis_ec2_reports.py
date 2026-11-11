"""resolver-endpoint-ip-addresses-are-exactly-the-enis-ec2-reports."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resolver-endpoint-ip-addresses-are-exactly-the-enis-ec2-reports"
GROUP = "resolver-endpoint"
SERVICES = ["route53resolver"]

_SCENARIO = "r53r-endpoint-enis"

_CIDR = "10.65.0.0/16"
_BASE = _CIDR.split("/")[0].rsplit(".", 2)[0]


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _drop(what, fn, ident):
    """Bounded delete that tolerates a dependency still draining; a delete that never succeeds
    is reported with its id rather than swallowed."""
    deadline = time.time() + 300
    last = None
    while time.time() < deadline:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code") or ""
            # Already gone is success. `InvalidChangeBatch` is Route 53's answer when a record
            # set being deleted is not there, and `NoSuch*` is its answer for a missing zone.
            if "NotFound" in code or "NoSuch" in code or code == "InvalidChangeBatch":
                return
            last = exc
            time.sleep(3)
    raise RuntimeError(f"{what} {ident} was not deleted: {last}")


def _rig_vpc(ctx, scenario, subnet_count):
    """Create a dedicated VPC with `subnet_count` subnets in distinct AZs; return ids.

    A default VPC may lack subnets in two AZs, so none is relied on; a quota refusal fails loudly.
    """
    ec2 = ctx.client("ec2")
    kv = [{"Key": "sim2real", "Value": scenario}]
    spec = [{"ResourceType": "vpc", "Tags": kv}]
    try:
        vpc_id = ec2.create_vpc(CidrBlock=_CIDR, TagSpecifications=spec)["Vpc"]["VpcId"]
    except ClientError as exc:
        raise AssertionError(
            "this check must own its VPC (B10: no ambient default VPC) and create_vpc was "
            f"refused: {exc.response.get('Error', {}).get('Code')!r} -- {exc}") from exc
    ctx.on_cleanup(lambda v=vpc_id: _drop("vpc", lambda: ec2.delete_vpc(VpcId=v), v))
    # Route 53 Resolver answers at 169.254.169.253 only when DNS support is on, and creates its
    # autodefined rules only when DNS hostnames is on. Both are set explicitly rather than
    # inherited, because a non-default VPC defaults EnableDnsHostnames to false.
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = sorted(
        a["ZoneName"] for a in ec2.describe_availability_zones(Filters=[
            {"Name": "state", "Values": ["available"]},
            {"Name": "opt-in-status", "Values": ["opt-in-not-required"]},
        ])["AvailabilityZones"])
    assert len(azs) >= subnet_count, (
        f"region {ctx.region} exposes {len(azs)} usable AZs and this check needs {subnet_count} "
        f"distinct ones: {azs!r}")
    subnets = []
    for i, az in enumerate(azs[:subnet_count]):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"{_BASE}.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": kv}])["Subnet"]["SubnetId"]
        subnets.append(sid)
        ctx.on_cleanup(lambda x=sid: _drop("subnet", lambda: ec2.delete_subnet(SubnetId=x), x))
    groups = ec2.describe_security_groups(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "group-name", "Values": ["default"]}])["SecurityGroups"]
    assert groups, (
        f"the VPC {vpc_id} this check just created reports no default security group, so nothing "
        f"can be placed in it")
    return vpc_id, subnets, groups[0]["GroupId"]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _outbound_endpoint(ctx, r53, vpc_id, subnets, sg_id, kv):
    """An OUTBOUND Resolver endpoint with one IP per subnet; returns (id, release).

    An endpoint needs at least two IP addresses (a fixed API minimum). `release` deletes it and
    waits, minutes, for its ENIs to go; the body calls it so the VPC teardown can succeed.
    """
    assert len(subnets) >= 2, (
        f"an OUTBOUND Resolver endpoint needs IP addresses in at least 2 subnets, got {subnets!r}")
    ep_id = r53.create_resolver_endpoint(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-r53r-ep-")[:64],
        SecurityGroupIds=[sg_id], Direction="OUTBOUND",
        IpAddresses=[{"SubnetId": s} for s in subnets],
        Tags=kv)["ResolverEndpoint"]["Id"]

    released = {"done": False}

    def release(budget=900):
        if released["done"]:
            return
        released["done"] = True
        try:
            r53.delete_resolver_endpoint(ResolverEndpointId=ep_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        deadline = time.time() + budget
        while True:
            try:
                r53.get_resolver_endpoint(ResolverEndpointId=ep_id)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                    return
                raise
            if time.time() >= deadline:
                break
            time.sleep(2)
        if _budget_spent(ctx):
            raise TimeoutError(f"resolver endpoint {ep_id} to disappear: the run budget ended first; not graded")
        raise RuntimeError(f"resolver endpoint {ep_id} never disappeared")

    ctx.on_cleanup(release)

    # CREATING -> OPERATIONAL is real ENI provisioning; the status is the observable condition and
    # ACTION_NEEDED must never be admitted as terminal.
    seen = []
    deadline = time.time() + _budget_s(ctx, 900)
    while True:
        seen.append(r53.get_resolver_endpoint(ResolverEndpointId=ep_id)["ResolverEndpoint"])
        status = seen[-1]["Status"]
        if status == "OPERATIONAL":
            break
        if status == "CREATING" and time.time() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"outbound endpoint {ep_id} to become OPERATIONAL: the run budget ended first; not graded")
        assert status == "CREATING" and time.time() < deadline, (
            f"the outbound endpoint {ep_id} reached {status!r} instead of OPERATIONAL: "
            f"{seen[-1].get('StatusMessage')!r}")
        time.sleep(1)
    assert seen[-1]["IpAddressCount"] == len(subnets), (
        f"the endpoint reports {seen[-1]['IpAddressCount']} IP addresses, expected one per "
        f"requested subnet ({len(subnets)})")
    return ep_id, release


def _await_rule_assoc(r53, assoc_id, budget=420):
    """Poll a resolver rule association to COMPLETE; FAILED must not be admitted as terminal."""
    seen = []
    deadline = time.time() + budget
    while True:
        seen.append(r53.get_resolver_rule_association(
            ResolverRuleAssociationId=assoc_id)["ResolverRuleAssociation"]["Status"])
        if seen[-1] == "COMPLETE":
            return seen
        assert seen[-1] in ("CREATING", "OVERRIDDEN") and time.time() < deadline, (
            f"the resolver rule association reached {seen[-1]!r}, not COMPLETE; the statuses "
            f"seen were {seen[-8:]!r}")
        time.sleep(2)


def _associate_rule(ctx, r53, rule_id, vpc_id):
    """Associate a resolver rule with the VPC; return (assoc_id, release)."""
    assoc_id = r53.associate_resolver_rule(
        ResolverRuleId=rule_id, VPCId=vpc_id,
        Name=ctx.unique_name("sim2real-r53r-rra-")[:64])["ResolverRuleAssociation"]["Id"]

    released = {"done": False}

    def release():
        if released["done"]:
            return
        released["done"] = True
        try:
            r53.disassociate_resolver_rule(ResolverRuleId=rule_id, VPCId=vpc_id)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("ResourceNotFoundException", "InvalidRequestException"):
                raise
        deadline = time.time() + 420
        while time.time() < deadline:
            try:
                r53.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                    return
                raise
            time.sleep(2)
        raise RuntimeError(f"resolver rule association {assoc_id} never disappeared")

    ctx.on_cleanup(release)
    return assoc_id, release


@tags("axis:happy-path", "concern:e2e", "plane:control", "cap:c1", "cap:c5")

def run(ctx) -> None:
    """A Resolver endpoint's IP addresses equal the ENIs EC2 reports (joined by private IP) across
    an add and a remove, and deleting the endpoint removes its ENIs and makes the id unusable.
    """
    r53 = ctx.client("route53resolver")
    ec2 = ctx.client("ec2")
    kv = [{"Key": "sim2real", "Value": _SCENARIO}]

    vpc_id, subnets, sg_id = _rig_vpc(ctx, _SCENARIO, 2)
    ep_id, release_ep = _outbound_endpoint(ctx, r53, vpc_id, subnets, sg_id, kv)

    def endpoint_ips():
        ips = r53.list_resolver_endpoint_ip_addresses(
            ResolverEndpointId=ep_id)["IpAddresses"]
        assert ips, f"the endpoint {ep_id} reports no IP addresses at all"
        return {a["Ip"] for a in ips if a["Status"] == "ATTACHED"}

    def vpc_eni_ips():
        return {e["PrivateIpAddress"]: e for e in ec2.describe_network_interfaces(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["NetworkInterfaces"]}

    def _converge(want_count, what):
        """Hold both views until Resolver AND EC2 agree on `want_count` addresses."""
        deadline = time.time() + _budget_s(ctx, 600)
        while True:
            ips = endpoint_ips()
            enis = vpc_eni_ips()
            if len(ips) == want_count and ips <= set(enis):
                return ips, enis
            if time.time() >= deadline and _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            assert time.time() < deadline, (
                f"{what}: the endpoint reports {sorted(ips)!r} and the VPC holds ENIs for "
                f"{sorted(enis)!r}, expected {want_count} addresses present in both")
            time.sleep(1)

    # _converge already established count and IP overlap; below are subnet, creator and mapping.
    ips2, enis2 = _converge(2, "the endpoint's initial addresses never matched its ENIs")
    for ip in sorted(ips2):
        eni = enis2[ip]
        assert eni["SubnetId"] in subnets, (
            f"the ENI carrying {ip} sits in {eni['SubnetId']!r}, which is not one of the subnets "
            f"this check gave the endpoint ({subnets!r})")
        assert eni.get("RequesterManaged") is True, (
            f"the ENI carrying {ip} is not requester-managed, so Resolver did not create it: "
            f"{eni.get('RequesterManaged')!r}")
    assert {enis2[ip]["SubnetId"] for ip in ips2} == set(subnets), (
        f"the endpoint's two ENIs are not one per requested subnet: "
        f"{ {ip: enis2[ip]['SubnetId'] for ip in ips2} !r}")

    # Add a third address in the first subnet; the new ENI is what is graded.
    r53.associate_resolver_endpoint_ip_address(
        ResolverEndpointId=ep_id, IpAddress={"SubnetId": subnets[0]})
    ips3, enis3 = _converge(3, "adding an IP address never produced a third ENI")
    added = ips3 - ips2
    assert len(added) == 1, (
        f"adding one IP address changed the endpoint's address set by {sorted(added)!r}, expected "
        f"exactly one new address on top of {sorted(ips2)!r}")
    new_ip = added.pop()
    assert enis3[new_ip]["SubnetId"] == subnets[0], (
        f"the new ENI landed in {enis3[new_ip]['SubnetId']!r} instead of the requested subnet "
        f"{subnets[0]!r}")
    assert r53.get_resolver_endpoint(
        ResolverEndpointId=ep_id)["ResolverEndpoint"]["IpAddressCount"] == 3, (
        "GetResolverEndpoint still reports a stale IpAddressCount after a third ENI appeared in "
        f"EC2 for {new_ip}")

    # The removed address's ENI must leave the VPC, not merely Resolver's list.
    r53.disassociate_resolver_endpoint_ip_address(
        ResolverEndpointId=ep_id, IpAddress={"SubnetId": subnets[0], "Ip": new_ip})
    deadline = time.time() + _budget_s(ctx, 600)
    while True:
        ips = endpoint_ips()
        enis = vpc_eni_ips()
        if len(ips) == 2 and new_ip not in ips and new_ip not in enis:
            break
        if time.time() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"{new_ip} to leave the endpoint and the VPC: the run budget ended first; not graded")
        assert time.time() < deadline, (
            f"removing {new_ip} left the endpoint reporting {sorted(ips)!r} and the VPC holding "
            f"ENIs for {sorted(enis)!r}; expected {new_ip} gone from both")
        time.sleep(1)
    assert ips == ips2, (
        f"removing the added address did not return the endpoint to its original two: "
        f"{sorted(ips)!r} vs {sorted(ips2)!r}")

    # Endpoint deletion tears down ENIs over minutes, so it runs in the body, not in cleanup.
    release_ep(_budget_s(ctx, 900))
    code, message = _error(lambda: r53.get_resolver_endpoint(ResolverEndpointId=ep_id))
    assert code == "ResourceNotFoundException", (
        f"reading the deleted endpoint {ep_id} returned {code!r}, expected "
        f"ResourceNotFoundException")
    assert message == f'[RSLVR-00501] Resolver endpoint with ID "{ep_id}" does not exist.', message
    code, message = _error(lambda: r53.associate_resolver_endpoint_ip_address(
        ResolverEndpointId=ep_id, IpAddress={"SubnetId": subnets[0]}))
    assert code == "ResourceNotFoundException", (
        f"mutating the deleted endpoint {ep_id} returned {code!r}, expected "
        f"ResourceNotFoundException")
    assert message == f'[RSLVR-00501] Resolver endpoint with ID "{ep_id}" does not exist.', message
    # ENI reclaim trails the endpoint's disappearance and no API reports when it finishes.
    deadline = time.time() + _budget_s(ctx, 600)
    while True:
        left = ips2 & set(vpc_eni_ips())
        if not left:
            break
        if time.time() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"endpoint {ep_id} ENIs to leave {vpc_id}: the run budget ended first; not graded")
        assert time.time() < deadline, (
            f"deleting endpoint {ep_id} left its ENIs behind in {vpc_id}: {sorted(left)!r}")
        time.sleep(1)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
