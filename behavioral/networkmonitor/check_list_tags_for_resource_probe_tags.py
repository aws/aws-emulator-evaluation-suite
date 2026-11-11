"""list-tags-for-resource-probe-tags."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-tags-for-resource-probe-tags"
GROUP = "tagging"
SERVICES = ["networkmonitor"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags supplied on CreateProbe are stored against the probe's own ARN, distinct from the
    parent monitor's tags, and are retrievable via ListTagsForResource(probeArn).
    """
    nm = ctx.client("networkmonitor")
    subnet_arn = _subnet_arn(ctx)
    monitor_name = ctx.unique_name("sim2real-nwm-mon-")
    nm.create_monitor(monitorName=monitor_name, tags={"scope": "monitor"})
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=monitor_name))

    probe = nm.create_probe(
        monitorName=monitor_name,
        probe={"sourceArn": subnet_arn, "destination": "192.168.60.60", "protocol": "ICMP", "packetSize": 56},
        tags={"scope": "probe"},
    )
    probe_id = probe["probeId"]
    probe_arn = probe["probeArn"]
    ctx.on_cleanup(lambda: _delete_probe(ctx, monitor_name, probe_id))

    probe_tags = nm.list_tags_for_resource(resourceArn=probe_arn)["tags"]
    assert probe_tags.get("scope") == "probe", f"expected probe tag scope=probe, got {probe_tags.get('scope')!r}"

    monitor_arn = nm.get_monitor(monitorName=monitor_name)["monitorArn"]
    monitor_tags = nm.list_tags_for_resource(resourceArn=monitor_arn)["tags"]
    assert monitor_tags.get("scope") == "monitor", "monitor and probe tags must not be conflated"


def _subnet_arn(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.79.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nwm-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    az = next(z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"] if z["State"] == "available")
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.79.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nwm-subnet-")}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:ec2:{ctx.region}:{account_id}:subnet/{subnet_id}"


def _delete_probe(ctx, monitor_name, probe_id):
    from botocore.exceptions import ClientError

    try:
        ctx.client("networkmonitor").delete_probe(monitorName=monitor_name, probeId=probe_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
