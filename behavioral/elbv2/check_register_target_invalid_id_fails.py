"""register-target-invalid-id-fails."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-target-invalid-id-fails"
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
    """RegisterTargets rejects a well-formed but nonexistent instance ID on an 'instance' target group
    with ValidationError (not the modeled InvalidTargetException) and does not add it, while a real
    EC2 instance registers on the same target group."""

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
        """Call fn(); return its error (code, message), retrying throttles. A success raises."""
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

    def _launch_probe_instance(subnet_id):
        ami = ctx.client("ssm").get_parameter(
            Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
        )["Parameter"]["Value"]
        reservation = _retry_throttled(lambda: ec2.run_instances(
            ImageId=ami,
            InstanceType="t3.micro",
            MinCount=1,
            MaxCount=1,
            SubnetId=subnet_id,
            TagSpecifications=[{
                "ResourceType": "instance",
                "Tags": _tags_kv() + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-inst-")}],
            }],
        ))
        instance_id = reservation["Instances"][0]["InstanceId"]
        ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
        ec2.get_waiter("instance_running").wait(
            InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 100}
        )
        return instance_id

    tg = _create_target_group(TargetType="instance", Port=80, Protocol="HTTP")
    vpc_id, subnet_ids = _setup_network()

    bogus_id = "i-0123456789abcdef0"
    code, message = _error(
        lambda: elb.register_targets(
            TargetGroupArn=tg["TargetGroupArn"],
            Targets=[{"Id": bogus_id, "Port": 80}],
        )
    )
    assert code == "ValidationError", f"expected validation error, got {code}"
    expected = f"The following targets are not valid instances: '{bogus_id}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    registered_ids = [
        d["Target"]["Id"]
        for d in elb.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])["TargetHealthDescriptions"]
    ]
    assert bogus_id not in registered_ids, f"rejected target must not be registered, got {registered_ids}"

    # Positive control: a real EC2 instance registers fine on the same target group.
    instance_id = _launch_probe_instance(subnet_ids[0])
    elb.register_targets(
        TargetGroupArn=tg["TargetGroupArn"],
        Targets=[{"Id": instance_id, "Port": 80}],
    )
    ctx.on_cleanup(lambda: elb.deregister_targets(
        TargetGroupArn=tg["TargetGroupArn"], Targets=[{"Id": instance_id, "Port": 80}]
    ))
    registered_ids_after = [
        d["Target"]["Id"]
        for d in elb.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])["TargetHealthDescriptions"]
    ]
    assert instance_id in registered_ids_after, f"expected {instance_id} registered, got {registered_ids_after}"



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
