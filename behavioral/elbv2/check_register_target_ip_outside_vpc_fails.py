"""register-target-ip-outside-vpc-fails."""
from __future__ import annotations

import ipaddress
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-target-ip-outside-vpc-fails"
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
    """RegisterTargets on an ip target group fails with ValidationError for a public address outside
    the VPC CIDR and RFC1918/RFC6598, and the address is not added; an in-VPC address is accepted."""

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
        """Call fn(), retrying throttling; return its error (code, message). A success raises."""
        delays = [3, 6, 12, 24, 30]
        for attempt in range(attempts):
            try:
                result = fn()
            except ClientError as exc:
                err = exc.response.get("Error", {})
                if err.get("Code") in _THROTTLE_CODES:
                    time.sleep(delays[min(attempt, len(delays) - 1)])
                    continue
                return err.get("Code"), err.get("Message")
            raise AssertionError(f"expected rejection but the call SUCCEEDED and returned {result!r}")
        raise AssertionError("exhausted retries on throttling")

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
        ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
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
            ctx.on_cleanup(lambda sid=sid: ec2.delete_subnet(SubnetId=sid))
        _net_cache["net"] = (vpc_id, subnet_ids)
        return _net_cache["net"]

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

    def _vpc_cidr():
        vpc_id, _ = _setup_network()
        return ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["CidrBlock"]

    tg = _create_target_group(TargetType="ip", Port=80, Protocol="HTTP")
    cidr = _vpc_cidr()
    # 203.0.113.0/24 is the TEST-NET-3 documentation range: never a VPC CIDR.
    outside_ip = "203.0.113.55"
    assert not cidr.startswith("203.0.113."), f"unexpected VPC CIDR overlap: {cidr}"

    # An in-VPC address must succeed, so the rejection below is not "rejects everything".
    inside_ip = str(ipaddress.ip_network(cidr).network_address + 50)
    _retry_throttled(lambda: elb.register_targets(
        TargetGroupArn=tg["TargetGroupArn"], Targets=[{"Id": inside_ip, "Port": 80}],
    ))
    ctx.on_cleanup(lambda: elb.deregister_targets(
        TargetGroupArn=tg["TargetGroupArn"], Targets=[{"Id": inside_ip, "Port": 80}],
    ))
    registered_ids = [
        d["Target"]["Id"]
        for d in elb.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])["TargetHealthDescriptions"]
    ]
    assert inside_ip in registered_ids, f"positive control failed: {inside_ip} missing from {registered_ids}"

    code, message = _error(
        lambda: elb.register_targets(
            TargetGroupArn=tg["TargetGroupArn"],
            Targets=[{"Id": outside_ip, "Port": 80}],
        )
    )
    assert code == "ValidationError", f"expected validation error, got {code}"
    expected = (
        f"The IP address '{outside_ip}' is not allowed, as it must be an address from a VPC subnet, "
        "RFC1918, or RFC6598"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    registered_ids_after = [
        d["Target"]["Id"]
        for d in elb.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])["TargetHealthDescriptions"]
    ]
    assert outside_ip not in registered_ids_after, "the rejected out-of-range target must not have been added"



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
