"""network-config-error-semantics."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "network-config-error-semantics"
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
    """SetIpAddressType/SetSecurityGroups/ModifyIpPools/SetSubnets raise LoadBalancerNotFound for a
    fabricated ARN; on a live LB each first succeeds with valid input, then invalid SG/subnet inputs
    and dualstack-on-internal raise their specific validation errors."""

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

    def _error(fn):
        """Call fn(); return the (code, message) of the ClientError it raises, retrying throttles.
        A success raises."""
        delays = [3, 6, 12, 24, 30]
        err = {}
        for attempt in range(5):
            try:
                result = fn()
            except ClientError as exc:
                err = exc.response.get("Error", {})
            else:
                raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")
            if err.get("Code") not in _THROTTLE_CODES:
                break
            time.sleep(delays[attempt])
        return err.get("Code"), err.get("Message")

    def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

    def _setup_network(num_subnets=2):
        if _net_cache:
            return _net_cache["net"]
        default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
        if default_vpcs:
            vpc_id = default_vpcs[0]["VpcId"]
            subnets = ec2.describe_subnets(Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
            ])["Subnets"]
            per_az = {}
            for subnet in sorted(subnets, key=lambda s: s["SubnetId"]):
                per_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
            subnet_ids = [per_az[az] for az in sorted(per_az)][:num_subnets]
            if len(subnet_ids) >= min(num_subnets, 2):
                _net_cache["net"] = (vpc_id, subnet_ids)
                return _net_cache["net"]
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
        try:
            ec2.create_tags(Resources=[vpc_id], Tags=_tags_kv() + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}])
        except Exception:
            pass
        azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        subnet_ids = []
        for i in range(num_subnets):
            az = azs[i % len(azs)]["ZoneName"]
            sid = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=az)["Subnet"]["SubnetId"]
            subnet_ids.append(sid)
            ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
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

    _ids = {}

    def _account_id():
        if "acct" not in _ids:
            _ids["acct"] = ctx.client("sts").get_caller_identity()["Account"]
        return _ids["acct"]

    def _fake_lb_arn(lb_type="app"):
        return (f"arn:aws:elasticloadbalancing:{ctx.region}:{_account_id()}:"
                f"loadbalancer/{lb_type}/sim2real-behav-missing/0000000000000000")

    def _fake_listener_arn(lb_type="app"):
        return (f"arn:aws:elasticloadbalancing:{ctx.region}:{_account_id()}:"
                f"listener/{lb_type}/sim2real-behav-missing/0000000000000000/1111111111111111")

    def _fake_tg_arn():
        return (f"arn:aws:elasticloadbalancing:{ctx.region}:{_account_id()}:"
                "targetgroup/sim2real-behav-missing/0000000000000000")

    def _fake_trust_store_arn():
        return (f"arn:aws:elasticloadbalancing:{ctx.region}:{_account_id()}:"
                "truststore/sim2real-behav-missing/0000000000000000")

    missing = _fake_lb_arn()

    err = _error(
        lambda: elb.set_ip_address_type(LoadBalancerArn=missing, IpAddressType="ipv4")
    )
    assert err == ("LoadBalancerNotFound", f"Load balancer '{missing}' not found"), err

    err = _error(
        lambda: elb.set_security_groups(LoadBalancerArn=missing, SecurityGroups=["sg-0000000000000000"])
    )
    assert err == ("LoadBalancerNotFound", f"Load balancer '{missing}' not found"), err

    err = _error(
        lambda: elb.modify_ip_pools(
            LoadBalancerArn=missing,
            IpamPools={"Ipv4IpamPoolId": "ipam-pool-0000000000000000"},
        )
    )
    assert err == ("LoadBalancerNotFound", f"Load balancer '{missing}' not found"), err

    _, two = _setup_network(num_subnets=2)
    err = _error(lambda: elb.set_subnets(LoadBalancerArn=missing, Subnets=two))
    assert err == ("LoadBalancerNotFound", f"Load balancer '{missing}' not found"), err

    vpc_id, _ = _setup_network()
    lb = _create_load_balancer(subnet_ids=two, Scheme="internal")
    arn = lb["LoadBalancerArn"]
    _wait_for_lb_active(arn)

    default_sg = ec2.describe_security_groups(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "group-name", "Values": ["default"]},
    ])["SecurityGroups"][0]["GroupId"]
    _retry_throttled(lambda: elb.set_security_groups(LoadBalancerArn=arn, SecurityGroups=[default_sg]))
    described = elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]
    assert described.get("SecurityGroups") == [default_sg], described.get("SecurityGroups")

    err = _error(
        lambda: elb.set_security_groups(LoadBalancerArn=arn, SecurityGroups=["sg-0000000000000000"])
    )
    # message varies: it embeds the per-request EC2 Request ID.
    assert err[0] == "InvalidSecurityGroup", err

    _retry_throttled(lambda: elb.set_subnets(LoadBalancerArn=arn, Subnets=two))
    described = elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]
    assert len(described["AvailabilityZones"]) == 2, described["AvailabilityZones"]

    err = _error(
        lambda: elb.set_subnets(LoadBalancerArn=arn, Subnets=[two[0], "subnet-0000000000000000"])
    )
    assert err == ("SubnetNotFound", "InvalidSubnetID.NotFound"), err

    _retry_throttled(lambda: elb.set_ip_address_type(LoadBalancerArn=arn, IpAddressType="ipv4"))
    described = elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]
    assert described["IpAddressType"] == "ipv4", described["IpAddressType"]

    err = _error(
        lambda: elb.set_ip_address_type(LoadBalancerArn=arn, IpAddressType="dualstack")
    )
    assert err == ("ValidationError", "You must specify subnets with an associated IPv6 CIDR block."), err

    described = elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]
    assert len(described["AvailabilityZones"]) == 2, described["AvailabilityZones"]
    assert described["IpAddressType"] == "ipv4", described["IpAddressType"]



# Load balancers delete asynchronously: their ENIs linger in the subnet / security group, so an
# immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait
# (bounded) for the ENIs to go, retry inside one shared window, then fail naming the ENIs left.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


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
