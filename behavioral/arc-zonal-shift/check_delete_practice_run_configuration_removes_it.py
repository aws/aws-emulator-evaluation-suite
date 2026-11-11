"""delete-practice-run-configuration-removes-it."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-practice-run-configuration-removes-it"
GROUP = "state"
SERVICES = ["arc-zonal-shift"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeletePracticeRunConfiguration removes the practiceRunConfiguration from
    GetManagedResource and resets zonalAutoshiftStatus/practiceRunStatus back to DISABLED."""
    arc = ctx.client("arc-zonal-shift")
    lb_arn, _ = _create_nlb_managed_resource(ctx)
    _, outcome_alarm_arn = _create_ok_alarm(ctx)
    arc.create_practice_run_configuration(
        resourceIdentifier=lb_arn,
        outcomeAlarms=[{"type": "CLOUDWATCH", "alarmIdentifier": outcome_alarm_arn}],
    )

    with_config = arc.get_managed_resource(resourceIdentifier=lb_arn)
    assert with_config.get("practiceRunConfiguration") is not None, (
        f"expected practiceRunConfiguration to be present after create, got {with_config.get('practiceRunConfiguration')!r}"
    )

    arc.delete_practice_run_configuration(resourceIdentifier=lb_arn)

    without_config = arc.get_managed_resource(resourceIdentifier=lb_arn)
    assert without_config.get("practiceRunConfiguration") is None, (
        f"expected practiceRunConfiguration to be gone after delete, got {without_config.get('practiceRunConfiguration')!r}"
    )
    assert without_config["zonalAutoshiftStatus"] == "DISABLED", (
        f"expected zonalAutoshiftStatus DISABLED after delete, got {without_config['zonalAutoshiftStatus']!r}"
    )

    # Deleting again now that no configuration exists is an idempotent no-op, not a
    # conflict: the call must not raise, and it must not disturb the already-absent state.
    arc.delete_practice_run_configuration(resourceIdentifier=lb_arn)
    still_without_config = arc.get_managed_resource(resourceIdentifier=lb_arn)
    assert still_without_config.get("practiceRunConfiguration") is None, (
        f"expected practiceRunConfiguration to remain absent after the repeat delete, "
        f"got {still_without_config.get('practiceRunConfiguration')!r}"
    )

    # Reusability: the identifier is not permanently blocked by the delete -- a new
    # configuration can be created on it, at the independent read.
    arc.create_practice_run_configuration(
        resourceIdentifier=lb_arn,
        outcomeAlarms=[{"type": "CLOUDWATCH", "alarmIdentifier": outcome_alarm_arn}],
    )
    ctx.on_cleanup(lambda: _delete_config_if_present(arc, lb_arn))
    reused = arc.get_managed_resource(resourceIdentifier=lb_arn)
    assert reused.get("practiceRunConfiguration") is not None, (
        f"expected practiceRunConfiguration to be recreatable after deletion, got {reused.get('practiceRunConfiguration')!r}"
    )


def _delete_config_if_present(arc, resource_arn):
    try:
        arc.delete_practice_run_configuration(resourceIdentifier=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_ok_alarm(ctx):
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-arczs-alarm-")
    cw.put_metric_alarm(
        AlarmName=name,
        MetricName="CPUUtilization",
        Namespace="AWS/EC2",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=99.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))
    arn = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]["AlarmArn"]
    return name, arn


def _create_nlb_managed_resource(ctx):
    """Provision an internal NLB spanning 2 AZs and wait for ARC to auto-register it as a
    managed resource. Returns (load_balancer_arn, away_from_az_id)."""
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    arc = ctx.client("arc-zonal-shift")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to provision an ARC managed load balancer")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network does not span at least 2 Availability Zones in this region")
    subnet_ids = [by_az[az] for az in sorted(by_az)[:2]]

    name = ctx.unique_name("sim2realarczs")[:32].strip("-")
    lb = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        Scheme="internal",
        Type="network",
        IpAddressType="ipv4",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    elbv2.get_waiter("load_balancer_available").wait(
        LoadBalancerArns=[lb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )

    # ARC never discovers a load balancer as a managed resource on its own -- zonal shift
    # integration is an explicit opt-in attribute. Without this, GetManagedResource answers
    # AccessDeniedException("... is not a managed resource ...") forever, not transiently.
    elbv2.modify_load_balancer_attributes(
        LoadBalancerArn=lb_arn,
        Attributes=[{"Key": "zonal_shift.config.enabled", "Value": "true"}],
    )

    deadline = time.monotonic() + 900.0
    resource = None
    while time.monotonic() < deadline:
        try:
            resource = arc.get_managed_resource(resourceIdentifier=lb_arn)
            if resource.get("appliedWeights"):
                break
        except (arc.exceptions.ResourceNotFoundException, arc.exceptions.AccessDeniedException):
            pass
        time.sleep(2)
    if not resource or not resource.get("appliedWeights"):
        raise AssertionError(
            f"load balancer {lb_arn} was never registered as an ARC managed resource "
            "within 15 minutes"
        )
    away_from = sorted(resource["appliedWeights"])[0]
    return lb_arn, away_from


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
