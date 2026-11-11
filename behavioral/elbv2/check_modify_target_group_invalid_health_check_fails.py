"""modify-target-group-invalid-health-check-fails."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-target-group-invalid-health-check-fails"
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
    """ModifyTargetGroup with a health-check timeout longer than its interval fails with ValidationError and the
    exact message and leaves interval 30 / timeout 5, which a valid ModifyTargetGroup on the same group set."""

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

    tg = _create_target_group()
    arn = tg["TargetGroupArn"]

    # Positive control: the identical call shape, a valid (timeout < interval) pair, must succeed.
    control = _retry_throttled(lambda: elb.modify_target_group(
        TargetGroupArn=arn,
        HealthCheckIntervalSeconds=30,
        HealthCheckTimeoutSeconds=5,
    ))["TargetGroups"][0]
    assert (control["HealthCheckIntervalSeconds"], control["HealthCheckTimeoutSeconds"]) == (30, 5), (
        f"positive control did not apply (30, 5): got "
        f"({control['HealthCheckIntervalSeconds']}, {control['HealthCheckTimeoutSeconds']})"
    )

    code, message = _error(
        lambda: elb.modify_target_group(
            TargetGroupArn=arn,
            HealthCheckIntervalSeconds=5,
            HealthCheckTimeoutSeconds=30,
        )
    )
    assert code == "ValidationError", f"expected validation error, got {code}"
    expected = "Health check interval must be greater than the timeout."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect-absent: the rejected (interval=5, timeout=30) pair must not have been written; the
    # target group must still carry the positive control's (30, 5).
    after = _retry_throttled(lambda: elb.describe_target_groups(TargetGroupArns=[arn]))["TargetGroups"][0]
    assert (after["HealthCheckIntervalSeconds"], after["HealthCheckTimeoutSeconds"]) == (30, 5), (
        f"the rejected call still changed the health check to "
        f"({after['HealthCheckIntervalSeconds']}, {after['HealthCheckTimeoutSeconds']}); a refused "
        f"ModifyTargetGroup must leave (30, 5) untouched"
    )


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
