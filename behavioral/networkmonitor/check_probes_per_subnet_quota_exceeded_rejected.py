"""probes-per-subnet-quota-exceeded-rejected."""
from __future__ import annotations


from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "probes-per-subnet-quota-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["networkmonitor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A 5th probe from one subnet in one monitor (default quota 4) fails with ValidationException
    "Maximum probes per subnet limit exceeded." and is not created; a probe from a different subnet
    is created, leaving 5 probes on the monitor."""
    nm = ctx.client("networkmonitor")
    net_a = _create_vpc_and_subnet(ctx, cidr_prefix="10.230")
    monitor_name = _create_monitor(ctx)

    probe_ids = []
    for i in range(4):
        resp = nm.create_probe(
            monitorName=monitor_name,
            probe={"sourceArn": net_a["subnet_arn"], "destination": f"203.0.113.{40 + i}",
                   "protocol": "ICMP", "packetSize": 56},
        )
        pid = resp["probeId"]
        probe_ids.append(pid)
        ctx.on_cleanup(lambda pid=pid: _delete_probe(ctx, monitor_name, pid))

    err = _expect_rejected(ctx, nm, monitor_name, lambda: nm.create_probe(
        monitorName=monitor_name,
        probe={"sourceArn": net_a["subnet_arn"], "destination": "203.0.113.99",
               "protocol": "ICMP", "packetSize": 56},
    ))
    code = err["Code"]
    message = err.get("Message", "")
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message}"
    expected = "Maximum probes per subnet limit exceeded."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    probes_on_monitor = nm.get_monitor(monitorName=monitor_name).get("probes", [])
    assert len(probes_on_monitor) == 4, (
        f"the rejected 5th probe must not have been created, found {len(probes_on_monitor)} probes"
    )

    # positive control: a probe on a different subnet is unaffected by subnet A's quota
    net_b = _create_vpc_and_subnet(ctx, cidr_prefix="10.231")
    ok_resp = nm.create_probe(
        monitorName=monitor_name,
        probe={"sourceArn": net_b["subnet_arn"], "destination": "203.0.113.99",
               "protocol": "ICMP", "packetSize": 56},
    )
    ok_pid = ok_resp["probeId"]
    ctx.on_cleanup(lambda: _delete_probe(ctx, monitor_name, ok_pid))

    # CreateProbe's own response omits sourceArn even though the model lists it — read it
    # back independently via GetProbe rather than trust the mutating call's echo.
    ok_probe = nm.get_probe(monitorName=monitor_name, probeId=ok_pid)
    assert ok_probe["sourceArn"] == net_b["subnet_arn"], (
        f"expected the subnet-B probe's sourceArn to be {net_b['subnet_arn']!r}, got {ok_probe['sourceArn']!r}"
    )

    # terminal read: independent of the create_probe call above, at get_monitor
    final_probes = nm.get_monitor(monitorName=monitor_name).get("probes", [])
    final_ids = {p["probeId"] for p in final_probes}
    assert ok_pid in final_ids, (
        f"positive-control probe {ok_pid} on subnet B must be visible via get_monitor, found {final_ids}"
    )
    assert len(final_probes) == 5, (
        f"expected 4 subnet-A probes + 1 subnet-B probe = 5 total via independent read, found {len(final_probes)}"
    )


def _expect_rejected(ctx, nm, monitor_name, fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises rather than returning
    a falsy sentinel."""
    from botocore.exceptions import ClientError

    try:
        resp = fn()
    except ClientError as e:
        return e.response["Error"]
    pid = resp.get("probeId")
    if pid:
        ctx.on_cleanup(lambda: _delete_probe(ctx, monitor_name, pid))
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {resp!r}")


def _create_vpc_and_subnet(ctx, cidr_prefix):
    ec2 = ctx.client("ec2")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    vpc_id = ec2.create_vpc(
        CidrBlock=f"{cidr_prefix}.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nm-vpc-")}],
        }],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=f"{cidr_prefix}.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{
            "ResourceType": "subnet",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nm-subnet-")}],
        }],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    subnet_arn = f"arn:aws:ec2:{ctx.region}:{account_id}:subnet/{subnet_id}"
    return {"vpc_id": vpc_id, "subnet_id": subnet_id, "subnet_arn": subnet_arn}


def _create_monitor(ctx, aggregation_period=30):
    nm = ctx.client("networkmonitor")
    name = ctx.unique_name("sim2real-nm-mon-")
    nm.create_monitor(monitorName=name, aggregationPeriod=aggregation_period)
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=name))
    return name


def _delete_probe(ctx, monitor_name, probe_id, timeout_s=300.0, interval_s=5.0):
    """Teardown: wait for the probe to leave PENDING (DeleteProbe refuses it there), delete it,
    and wait until it is gone so the monitor delete that follows is accepted."""
    import time
    from botocore.exceptions import ClientError

    nm = ctx.client("networkmonitor")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            state = nm.get_probe(monitorName=monitor_name, probeId=probe_id)["state"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if state not in ("PENDING", "DELETING"):
            try:
                nm.delete_probe(monitorName=monitor_name, probeId=probe_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        time.sleep(interval_s)
    raise AssertionError(f"teardown: probe {probe_id} still present after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
