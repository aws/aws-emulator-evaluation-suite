"""register-targets-wrong-type-id-rejected."""
from __future__ import annotations

import ipaddress
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-targets-wrong-type-id-rejected"
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
    """Registering an EC2 instance ID into an ip-type target group must fail with
    ValidationError, the rejected target must be absent from DescribeTargetHealth, and
    a real IP address registered on the identical target group must succeed."""

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
        """Call fn(); return its error (code, message), retrying throttles. An unexpected SUCCESS
        raises."""
        delays = [3, 6, 12, 24, 30]
        for attempt in range(5):
            try:
                result = fn()
            except ClientError as exc:
                err = exc.response.get("Error", {})
                if err.get("Code") in _THROTTLE_CODES:
                    time.sleep(delays[attempt])
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

    vpc_id, _subnet_ids = _setup_network()
    tg = _create_target_group(Protocol="HTTP", Port=80, TargetType="ip", vpc_id=vpc_id)

    bad_id = "i-0123456789abcdef0"
    code, message = _error(
        lambda: elb.register_targets(
            TargetGroupArn=tg["TargetGroupArn"],
            Targets=[{"Id": bad_id, "Port": 80}],
        )
    )
    assert code == "ValidationError", code
    expected = f"The IP address '{bad_id}' is not a valid IPv4 address"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    registered_ids = [
        d["Target"]["Id"]
        for d in elb.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])["TargetHealthDescriptions"]
    ]
    assert bad_id not in registered_ids, f"rejected instance-id target must not be registered: {registered_ids}"

    # Positive control: a real IP address inside the target group's own VPC is accepted
    # on the identical call shape, so the rejection above is specific to the id shape.
    vpc_cidr = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["CidrBlock"]
    valid_ip = str(ipaddress.ip_address(vpc_cidr.split("/")[0]) + 50)
    _retry_throttled(lambda: elb.register_targets(
        TargetGroupArn=tg["TargetGroupArn"], Targets=[{"Id": valid_ip, "Port": 80}],
    ))
    ctx.on_cleanup(lambda: elb.deregister_targets(
        TargetGroupArn=tg["TargetGroupArn"], Targets=[{"Id": valid_ip, "Port": 80}],
    ))
    registered_ids_after = [
        d["Target"]["Id"]
        for d in elb.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])["TargetHealthDescriptions"]
    ]
    assert valid_ip in registered_ids_after, f"valid ip target was not accepted: {registered_ids_after}"



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
