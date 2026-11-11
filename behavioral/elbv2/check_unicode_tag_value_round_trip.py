"""unicode-tag-value-round-trip."""
from __future__ import annotations

import time

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "unicode-tag-value-round-trip"
GROUP = "representation"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddTags round-trips a Unicode letter/digit key and value through DescribeTags codepoint-exact,
    and rejects an emoji (Symbol-category) value with ValidationError without persisting it."""
    vpc_id, subnet_ids, sg_id = _provision_alb_network(ctx)
    _lb, lb_arn = _create_alb(ctx, subnet_ids, sg_id)

    elbv2 = ctx.client("elbv2")
    key = "标签-Ключ-Nämé"
    value = "值-Значение-Wértê 42"
    elbv2.add_tags(ResourceArns=[lb_arn], Tags=[{"Key": key, "Value": value}])

    described = elbv2.describe_tags(ResourceArns=[lb_arn])["TagDescriptions"][0]["Tags"]
    matches = [t for t in described if t["Key"] == key]
    assert len(matches) == 1, f"unicode tag key not found byte-exact among {described}"
    assert matches[0]["Value"] == value, f"expected value {value!r}, got {matches[0]['Value']!r}"

    # The Tag Key/Value pattern excludes Symbol-category codepoints (e.g. emoji) -- AddTags with
    # an emoji value must be REJECTED with ValidationError, not silently accepted/truncated by a
    # permissive emulator. The round trip above is the positive control: it proves AddTags/
    # DescribeTags work on this exact resource before we probe the rejection.
    try:
        elbv2.add_tags(ResourceArns=[lb_arn], Tags=[{"Key": "emoji-key", "Value": "\U0001F680\U0001F389"}])
    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ValidationError", f"expected ValidationError for emoji tag value, got {code}"
        message = e.response["Error"].get("Message")
        expected = (
            "1 validation error detected: Value '\U0001F680\U0001F389' at 'tags.1.member.value' failed to satisfy "
            "constraint: Member must satisfy regular expression pattern: ^([\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*)$"
        )
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        raise AssertionError("AddTags with an emoji (Symbol-category) tag value should have raised ValidationError")

    # Effect-absent: the rejected call must not have persisted anything, via an independent read.
    described_after = elbv2.describe_tags(ResourceArns=[lb_arn])["TagDescriptions"][0]["Tags"]
    leaked = [t for t in described_after if t["Key"] == "emoji-key"]
    assert not leaked, f"rejected emoji tag was nonetheless persisted: {leaked}"


# ===== helpers =====

def _provision_alb_network(ctx):
    """Create a minimal VPC + 2 subnets (different AZs) + default SG, sufficient for an internal ALB."""
    ec2 = ctx.client("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.176.0.0/16")["Vpc"]
    vpc_id = vpc["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.create_tags(
        Resources=[vpc_id],
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
    )

    def _delete_vpc():
        _delete_net_gone_ok(ec2, "delete_vpc", VpcId=vpc_id)

    ctx.on_cleanup(_delete_vpc)

    azs = ec2.describe_availability_zones()["AvailabilityZones"]
    az_names = [az["ZoneName"] for az in azs if az["State"] == "available"][:2]
    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.176.{i}.0/24", AvailabilityZone=az)["Subnet"]
        sid = subnet["SubnetId"]
        subnet_ids.append(sid)

        def _delete_subnet(sid=sid):
            _delete_net_gone_ok(ec2, "delete_subnet", SubnetId=sid)

        ctx.on_cleanup(_delete_subnet)

    sg_id = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return vpc_id, subnet_ids, sg_id


def _create_alb(ctx, subnet_ids, sg_id):
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-behav-lb-")
    lb = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        SecurityGroups=[sg_id],
        Scheme="internal",
        Type="application",
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]

    def _delete_lb():
        try:
            elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                raise
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            try:
                elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
            except elbv2.exceptions.LoadBalancerNotFoundException:
                return
            time.sleep(2)

    ctx.on_cleanup(_delete_lb)
    return lb, lb_arn


def _delete_net_gone_ok(client, op, **ident):
    """Network teardown: an already-deleted VPC or subnet is clean; every other failure raises."""
    try:
        _delete_net(client, op, **ident)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"):
            raise


# A load balancer in this VPC deletes asynchronously and leaves its ENIs behind for a while, so an
# immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Teardown
# waits (bounded) for the ENIs, retries that code in one shared window, then raises naming the ENIs.
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
        _time.sleep(2)
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
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
