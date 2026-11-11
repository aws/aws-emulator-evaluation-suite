"""set-ip-address-type-dualstack-without-ipv6-rejected."""
from __future__ import annotations

import ipaddress
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-ip-address-type-dualstack-without-ipv6-rejected"
GROUP = 'overly-permissive'
SERVICES = ['elbv2']

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

def _clamp_name(name, maxlen=32):
    return name[:maxlen].rstrip("-")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Requesting dualstack on IPv4-only subnets must fail with ValidationError, and the
    identical call must succeed once every subnet has an IPv6 CIDR -- proving the rejection is
    scoped to the missing association rather than to SetIpAddressType(dualstack) in general."""

    _net_cache = {}
    elb = ctx.client("elbv2")
    ec2 = ctx.client("ec2")

    def _tags_kv():
        return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

    def _retry_throttled(fn, attempts=5):
        delays = [3, 6, 12, 24, 30]
        last_exc = None
        for attempt in range(attempts):
            try:
                return fn()
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code not in _THROTTLE_CODES:
                    raise
                last_exc = exc
                time.sleep(delays[min(attempt, len(delays) - 1)])
        raise last_exc

    def _error(fn, attempts=5):
        """Call fn(); return its error (code, message), retrying throttles; a success raises."""
        delays = [3, 6, 12, 24, 30]
        for attempt in range(attempts):
            try:
                result = fn()
            except ClientError as exc:
                err = exc.response.get("Error", {})
                if err.get("Code") in _THROTTLE_CODES and attempt < attempts - 1:
                    time.sleep(delays[min(attempt, len(delays) - 1)])
                    continue
                return err.get("Code"), err.get("Message")
            else:
                raise AssertionError(
                    f"expected the call to be rejected, but it succeeded and returned {result!r}"
                )
        raise AssertionError("exhausted retries against throttling")

    def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

    teardown: dict = {}

    def _setup_network(num_subnets=2):
        """A VPC the check owns, IPv4-only until the restore leg, with its own attached internet
        gateway and one subnet per zone; the teardown deletes all of it."""
        if _net_cache:
            return _net_cache["net"]
        name = ctx.unique_name("sim2real-behav-vpc-")

        def _spec(resource_type):
            return [{"ResourceType": resource_type, "Tags": _tags_kv() + [{"Key": "Name", "Value": name}]}]

        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16", TagSpecifications=_spec("vpc"))["Vpc"]["VpcId"]
        ctx.on_cleanup(lambda: _delete_net(ec2, teardown, "delete_vpc", VpcId=vpc_id))
        igw_id = ec2.create_internet_gateway(TagSpecifications=_spec("internet-gateway"))[
            "InternetGateway"]["InternetGatewayId"]
        ctx.on_cleanup(lambda: _delete_net(ec2, teardown, "delete_internet_gateway", InternetGatewayId=igw_id))
        ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        ctx.on_cleanup(lambda: _delete_net(
            ec2, teardown, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))
        azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        subnet_ids = []
        for i in range(num_subnets):
            az = azs[i % len(azs)]["ZoneName"]
            sid = ec2.create_subnet(
                VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=az, TagSpecifications=_spec("subnet"),
            )["Subnet"]["SubnetId"]
            subnet_ids.append(sid)
            ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, teardown, "delete_subnet", SubnetId=sid))
        _net_cache["net"] = (vpc_id, subnet_ids)
        return _net_cache["net"]

    def _create_load_balancer(name=None, subnet_ids=None, **kwargs):
        name = _clamp_name(name or ctx.unique_name("sim2real-behav-lb-"))
        if subnet_ids is None:
            _, subnet_ids = _setup_network()
        params = dict(
            Name=name,
            Subnets=subnet_ids,
            Type=kwargs.pop("Type", "application"),
            Scheme=kwargs.pop("Scheme", "internal"),
            Tags=kwargs.pop("Tags", _tags_kv()),
        )
        params.update(kwargs)
        lb = _retry_throttled(lambda: elb.create_load_balancer(**params))["LoadBalancers"][0]
        arn = lb["LoadBalancerArn"]
        ctx.on_cleanup(lambda: elb.delete_load_balancer(LoadBalancerArn=arn))
        return lb

    def _create_target_group(name=None, vpc_id=None, **kwargs):
        name = _clamp_name(name or ctx.unique_name("sim2real-behav-tg-"))
        params = dict(Name=name, Protocol="HTTP", Port=80, TargetType="ip")
        params.update(kwargs)
        if params.get("TargetType") != "lambda":
            if vpc_id is None:
                vpc_id, _ = _setup_network()
            params.setdefault("VpcId", vpc_id)
        elif vpc_id is not None:
            params["VpcId"] = vpc_id
        params.setdefault("Tags", _tags_kv())
        tg = _retry_throttled(lambda: elb.create_target_group(**params))["TargetGroups"][0]
        arn = tg["TargetGroupArn"]
        ctx.on_cleanup(lambda: _delete_target_group_when_free(elb, arn))
        return tg

    def _create_listener(load_balancer_arn, **kwargs):
        params = dict(LoadBalancerArn=load_balancer_arn, Protocol="HTTP", Port=80)
        params.update(kwargs)
        listener = _retry_throttled(lambda: elb.create_listener(**params))["Listeners"][0]
        arn = listener["ListenerArn"]
        ctx.on_cleanup(lambda: elb.delete_listener(ListenerArn=arn))
        return listener

    def _wait_for_lb_active(arn, timeout_s=230, interval_s=10):
        return _poll_until(
            lambda: elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0],
            lambda lb: lb["State"]["Code"] in ("active", "active_impaired", "failed"),
            timeout_s=timeout_s, interval_s=interval_s,
            description="load balancer reaching a terminal state",
        )

    # The IPv6 blocks the restore leg adds belong to the check's own VPC and subnets and go with them.
    def _ensure_vpc_ipv6_cidr(vpc_id):
        vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
        for assoc in vpc.get("Ipv6CidrBlockAssociationSet", []):
            if assoc["Ipv6CidrBlockState"]["State"] == "associated":
                return assoc["Ipv6CidrBlock"]
        resp = ec2.associate_vpc_cidr_block(VpcId=vpc_id, AmazonProvidedIpv6CidrBlock=True)
        assoc_id = resp["Ipv6CidrBlockAssociation"]["AssociationId"]
        vpc = _poll_until(
            lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0],
            lambda v: any(
                a["AssociationId"] == assoc_id and a["Ipv6CidrBlockState"]["State"] == "associated"
                for a in v.get("Ipv6CidrBlockAssociationSet", [])
            ),
            timeout_s=60, interval_s=2.0, description="VPC IPv6 CIDR block reaching associated",
        )
        return next(
            a["Ipv6CidrBlock"] for a in vpc["Ipv6CidrBlockAssociationSet"] if a["AssociationId"] == assoc_id
        )

    def _ensure_subnet_ipv6_cidr(subnet_id, ipv6_cidr):
        subnet = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]
        if any(
            a["Ipv6CidrBlockState"]["State"] == "associated"
            for a in subnet.get("Ipv6CidrBlockAssociationSet", [])
        ):
            return
        resp = ec2.associate_subnet_cidr_block(SubnetId=subnet_id, Ipv6CidrBlock=ipv6_cidr)
        assoc_id = resp["Ipv6CidrBlockAssociation"]["AssociationId"]
        _poll_until(
            lambda: ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0],
            lambda s: any(
                a["AssociationId"] == assoc_id and a["Ipv6CidrBlockState"]["State"] == "associated"
                for a in s.get("Ipv6CidrBlockAssociationSet", [])
            ),
            timeout_s=60, interval_s=2.0, description="subnet IPv6 CIDR block reaching associated",
        )

    vpc_id, subnet_ids = _setup_network(num_subnets=2)
    lb = _create_load_balancer(subnet_ids=subnet_ids)
    lb_arn = lb["LoadBalancerArn"]
    _wait_for_lb_active(lb_arn)

    baseline = elb.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
    assert baseline["IpAddressType"] == "ipv4", (
        f"expected a freshly created ALB on IPv4-only subnets to report ipv4, got {baseline['IpAddressType']!r}"
    )

    code, message = _error(
        lambda: elb.set_ip_address_type(LoadBalancerArn=lb_arn, IpAddressType="dualstack")
    )
    assert code == "ValidationError", f"expected ValidationError requesting dualstack without ipv6 subnets, got {code!r}"
    expected = "You must specify subnets with an associated IPv6 CIDR block."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unchanged = elb.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
    assert unchanged["IpAddressType"] == "ipv4", (
        f"the rejected SetIpAddressType call must not change state; expected ipv4, got {unchanged['IpAddressType']!r}"
    )

    # Restore leg: without this, a target that rejects EVERY SetIpAddressType(dualstack) call --
    # not just ones on IPv4-only subnets -- would pass the assertions above too. Giving every
    # subnet an IPv6 CIDR and re-issuing the identical call proves the rejection was scoped to the
    # missing IPv6 association, not to the operation itself.
    vpc_ipv6_cidr = _ensure_vpc_ipv6_cidr(vpc_id)
    subnet_ipv6_cidrs = list(ipaddress.ip_network(vpc_ipv6_cidr).subnets(new_prefix=64))
    for subnet_id, ipv6_cidr in zip(subnet_ids, subnet_ipv6_cidrs):
        _ensure_subnet_ipv6_cidr(subnet_id, str(ipv6_cidr))

    restored = _retry_throttled(
        lambda: elb.set_ip_address_type(LoadBalancerArn=lb_arn, IpAddressType="dualstack")
    )
    assert restored["IpAddressType"] == "dualstack", (
        f"expected the identical call to succeed once every subnet has an IPv6 CIDR, got {restored['IpAddressType']!r}"
    )

    confirmed = elb.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
    assert confirmed["IpAddressType"] == "dualstack", (
        f"expected DescribeLoadBalancers to reflect dualstack after the retry, got {confirmed['IpAddressType']!r}"
    )


# Load balancers delete asynchronously: their ENIs linger in the subnet / security group, so an
# immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait
# (bounded) for the ENIs to go, retry to the run's network deadline, then fail naming the ENIs left.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}


def _delete_net(client, teardown, op, **ident):
    from botocore.exceptions import ClientError as _ClientError

    # One deadline per run, started by the first network delete and held in the run's teardown dict.
    deadline = teardown.setdefault("deadline", time.monotonic() + _NET_TEARDOWN_S)
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and time.monotonic() < deadline:
        time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
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
        time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
