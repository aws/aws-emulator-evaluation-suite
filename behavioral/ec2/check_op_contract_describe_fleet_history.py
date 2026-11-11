"""op-contract-describeFleetHistory."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeFleetHistory"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeFleetHistory returns events scoped to a real fleet and rejects a bogus fleet ID."""
    ec2 = ctx.client("ec2")
    fleet_id, _lt_id = _create_zero_capacity_fleet(ctx)

    # --- success path: history is scoped to our fleet and echoes the request window ---
    start_time = datetime.now(timezone.utc) - timedelta(minutes=10)
    resp = _poll_until(
        lambda: ec2.describe_fleet_history(FleetId=fleet_id, StartTime=start_time),
        lambda r: r.get("FleetId") == fleet_id,
        timeout_s=30,
        interval_s=2,
    )
    assert resp["FleetId"] == fleet_id, f"expected FleetId {fleet_id!r}, got {resp.get('FleetId')!r}"
    # A maintain-type fleet pinned at TotalTargetCapacity=0 never launches, terminates or
    # modifies anything, so it never produces a history event: real AWS reports an empty
    # historyRecordSet for it every time.
    # An event-producing target would fail this, since it is asserting the absence exactly.
    assert resp["HistoryRecords"] == [], (
        f"expected no history records for an idle zero-capacity fleet, got {resp['HistoryRecords']!r}"
    )
    for record in resp["HistoryRecords"]:
        assert record["EventType"], f"history record missing EventType: {record!r}"
        assert record["Timestamp"], f"history record missing Timestamp: {record!r}"

    # --- error boundary: a well-formed but nonexistent fleet ID must be rejected specifically ---
    bogus_fleet_id = "fleet-00000000-0000-0000-0000-000000000000"

    def _call():
        ec2.describe_fleet_history(FleetId=bogus_fleet_id, StartTime=start_time)

    code, message = _error(_call)
    assert code == "InvalidFleetId.NotFound", f"expected InvalidFleetId.NotFound, got {code!r}"
    expected = f"The FleetId(s) {bogus_fleet_id} do not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Return fn()'s (code, message); a success raises, never reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _latest_amazon_linux_ami(ec2):
    resp = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023.*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )
    images = sorted(resp["Images"], key=lambda i: i["CreationDate"], reverse=True)
    if not images:
        resp = ec2.describe_images(
            Owners=["amazon"],
            Filters=[{"Name": "name", "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]}],
        )
        images = sorted(resp["Images"], key=lambda i: i["CreationDate"], reverse=True)
    if not images:
        raise AssertionError("no Amazon Linux AMI available to build a launch template")
    return images[0]["ImageId"]


def _create_zero_capacity_fleet(ctx):
    """Create a real, zero-cost EC2 Fleet (TotalTargetCapacity=0 launches nothing)."""
    ec2 = ctx.client("ec2")
    ami_id = _latest_amazon_linux_ami(ec2)
    name = ctx.unique_name("sim2real-fleet-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "Name", "Value": name}]}],
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    fleet = ec2.create_fleet(
        Type="maintain",
        LaunchTemplateConfigs=[
            {"LaunchTemplateSpecification": {"LaunchTemplateId": lt_id, "Version": "$Latest"}}
        ],
        TargetCapacitySpecification={"TotalTargetCapacity": 0, "DefaultTargetCapacityType": "on-demand"},
        TagSpecifications=[{"ResourceType": "fleet", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    fleet_id = fleet["FleetId"]
    ctx.on_cleanup(lambda: ec2.delete_fleets(FleetIds=[fleet_id], TerminateInstances=False))
    return fleet_id, lt_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
