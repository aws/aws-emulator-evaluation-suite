"""probe-unanswered-destination-reports-full-packet-loss."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "probe-unanswered-destination-reports-full-packet-loss"
GROUP = "data-plane"
SERVICES = ["networkmonitor"]


# timing:real-time — metric: 30 s
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An ACTIVE ICMP probe from an internet-routable VPC subnet to a public IP the check owns,
    where nothing replies, delivers AWS/NetworkMonitor PacketLoss datapoints of 100 to CloudWatch;
    CreateProbe/GetProbe alone without metric delivery does not satisfy it."""
    nm = ctx.client("networkmonitor")
    monitor_name = ctx.unique_name("sim2real-nwm-mon-")
    destination = _unanswering_public_ip(ctx, lambda: _monitor_gone(nm, monitor_name))
    subnet_arn, probe_id_hint = _create_public_subnet(ctx)

    created = nm.create_monitor(
        monitorName=monitor_name,
        aggregationPeriod=30,
        probes=[
            {
                "sourceArn": subnet_arn,
                "destination": destination,
                "protocol": "ICMP",
                "packetSize": 56,
            }
        ],
    )
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=monitor_name))
    # Registered after the monitor's delete, so it runs first: every probe goes before the monitor.
    ctx.on_cleanup(lambda: _delete_monitor_probes(ctx, monitor_name))
    assert created["state"] == "PENDING", f"expected initial state PENDING, got {created['state']!r}"

    monitor_after = _poll_until(
        lambda: nm.get_monitor(monitorName=monitor_name),
        lambda m: len(m.get("probes", [])) > 0,
        timeout_s=60.0,
        interval_s=5.0,
    )
    probe_id = monitor_after["probes"][0]["probeId"]

    probe_state = _poll_until(
        lambda: nm.get_probe(monitorName=monitor_name, probeId=probe_id)["state"],
        lambda s: s in ("ACTIVE", "ERROR"),
        # a monitor's first probe in an account can take well over ten minutes to provision
        timeout_s=1500.0,
        interval_s=15.0,
    )
    assert probe_state == "ACTIVE", f"probe failed to reach ACTIVE (managed infra provisioning), got {probe_state!r}"

    cw = ctx.client("cloudwatch")
    metric_dim = _poll_until(
        lambda: _find_probe_metric_dimensions(cw, probe_id, monitor_name),
        lambda d: d is not None,
        timeout_s=600.0,
        interval_s=20.0,
    )
    assert metric_dim is not None, "no AWS/NetworkMonitor metric ever appeared for this probe"

    datapoints = _poll_until(
        lambda: cw.get_metric_statistics(
            Namespace="AWS/NetworkMonitor",
            MetricName=metric_dim["metric_name"],
            Dimensions=metric_dim["dimensions"],
            StartTime=time.time() - 3600,
            EndTime=time.time(),
            Period=60,
            Statistics=["Average", "SampleCount"],
        )["Datapoints"],
        lambda dps: len(dps) > 0,
        timeout_s=300.0,
        interval_s=20.0,
    )
    assert metric_dim["metric_name"] == "PacketLoss", f"expected the PacketLoss metric, got {metric_dim!r}"
    assert len(datapoints) > 0, "expected at least one real CloudWatch datapoint for the ACTIVE probe"
    assert datapoints[0]["SampleCount"] > 0, (
        f"expected a positive SampleCount for a real ingested datapoint, got {datapoints[0]['SampleCount']!r}"
    )
    averages = sorted({dp["Average"] for dp in datapoints})
    assert averages == [100.0], f"a destination that never replies loses every packet; got {averages!r}"


# ===== helpers =====
def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _unanswering_public_ip(ctx, dependent_gone):
    """An Elastic IP the check allocates and leaves unassociated, so nothing answers on it.

    Its tags carry no sim2real mark, so only this check releases it, and it does so
    only once ``dependent_gone()`` proves the monitor is deleted, so a leaked probe never targets
    an address AWS hands to someone else; otherwise the address stays allocated."""
    ec2 = ctx.client("ec2")
    eip = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=[{"ResourceType": "elastic-ip", "Tags": [{"Key": "held-for", "Value": "network-monitor-probe"}]}],
    )

    def release():
        dependent_gone()
        ec2.release_address(AllocationId=eip["AllocationId"])

    ctx.on_cleanup(release)
    return eip["PublicIp"]


def _monitor_gone(nm, monitor_name, timeout_s=300.0, interval_s=5.0):
    """Return once GetMonitor answers ResourceNotFoundException; raise if the monitor remains."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            state = nm.get_monitor(monitorName=monitor_name).get("state")
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"monitor {monitor_name} still exists ({state}); its Elastic IP stays allocated")
        time.sleep(interval_s)


def _create_public_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.88.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nwm-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nwm-igw-")}]}]
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id))

    az = next(z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"] if z["State"] == "available")
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.88.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nwm-subnet-")}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[{"ResourceType": "route-table", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nwm-rt-")}]}]
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=rt_id))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)["AssociationId"]
    ctx.on_cleanup(lambda: ec2.disassociate_route_table(AssociationId=assoc_id))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:ec2:{ctx.region}:{account_id}:subnet/{subnet_id}", subnet_id


def _delete_monitor_probes(ctx, monitor_name, timeout_s=180.0, interval_s=2.0):
    """Delete every probe the monitor lists and wait until GetProbe answers not-found for each."""
    nm = ctx.client("networkmonitor")
    try:
        probes = [p["probeId"] for p in nm.get_monitor(monitorName=monitor_name).get("probes", [])]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    for probe_id in probes:
        try:
            nm.delete_probe(monitorName=monitor_name, probeId=probe_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    deadline = time.monotonic() + timeout_s
    for probe_id in probes:
        while True:
            try:
                nm.get_probe(monitorName=monitor_name, probeId=probe_id)
            except ClientError as e:
                if e.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                break
            if time.monotonic() >= deadline:
                raise TimeoutError(f"probe {probe_id} still present after DeleteProbe")
            time.sleep(interval_s)


def _find_probe_metric_dimensions(cw, probe_id, monitor_name):
    """The probe's PacketLoss metric (name and dimensions), or None until CloudWatch lists it."""
    kwargs = {"Namespace": "AWS/NetworkMonitor", "MetricName": "PacketLoss"}
    while True:
        resp = cw.list_metrics(**kwargs)
        for m in resp.get("Metrics", []):
            values = {d["Value"] for d in m.get("Dimensions", [])}
            if probe_id in values or monitor_name in values:
                return {"metric_name": m["MetricName"], "dimensions": m["Dimensions"]}
        if not resp.get("NextToken"):
            return None
        kwargs["NextToken"] = resp["NextToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
