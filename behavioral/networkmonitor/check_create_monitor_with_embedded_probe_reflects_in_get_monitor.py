"""create-monitor-with-embedded-probe-reflects-in-get-monitor."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-monitor-with-embedded-probe-reflects-in-get-monitor"
GROUP = "control-plane"
SERVICES = ["networkmonitor"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateMonitor(probes=[...]) provisions the embedded probe atomically with the monitor:
    GetMonitor lists it with matching configuration, and GetProbe can independently retrieve
    the exact same probe by the probeId GetMonitor reported.
    """
    nm = ctx.client("networkmonitor")
    subnet_arn = _subnet_arn(ctx)
    monitor_name = ctx.unique_name("sim2real-nwm-mon-")
    nm.create_monitor(
        monitorName=monitor_name,
        aggregationPeriod=60,
        probes=[{"sourceArn": subnet_arn, "destination": "192.168.62.62", "protocol": "ICMP", "packetSize": 72}],
    )
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=monitor_name))

    fetched = nm.get_monitor(monitorName=monitor_name)
    probes = fetched.get("probes", [])
    assert len(probes) == 1, f"expected exactly 1 embedded probe, got {len(probes)}"
    embedded = probes[0]
    probe_id = embedded["probeId"]
    ctx.on_cleanup(lambda: _delete_probe(ctx, monitor_name, probe_id))

    assert embedded["destination"] == "192.168.62.62", (
        f"expected embedded probe destination 192.168.62.62, got {embedded['destination']!r}"
    )
    assert embedded["protocol"] == "ICMP", f"expected embedded probe protocol ICMP, got {embedded['protocol']!r}"
    assert embedded["packetSize"] == 72, f"expected embedded probe packetSize 72, got {embedded['packetSize']!r}"
    assert embedded["sourceArn"] == subnet_arn, (
        f"expected embedded probe sourceArn {subnet_arn}, got {embedded['sourceArn']!r}"
    )

    standalone = nm.get_probe(monitorName=monitor_name, probeId=probe_id)
    assert standalone["destination"] == "192.168.62.62", (
        f"expected standalone probe destination 192.168.62.62, got {standalone['destination']!r}"
    )
    assert standalone["protocol"] == "ICMP", f"expected standalone probe protocol ICMP, got {standalone['protocol']!r}"
    assert standalone["packetSize"] == 72, f"expected standalone probe packetSize 72, got {standalone['packetSize']!r}"


def _subnet_arn(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.81.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nwm-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    az = next(z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"] if z["State"] == "available")
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.81.1.0/24",
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
