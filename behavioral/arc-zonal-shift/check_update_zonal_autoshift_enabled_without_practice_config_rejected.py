"""update-zonal-autoshift-enabled-without-practice-config-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-zonal-autoshift-enabled-without-practice-config-rejected"
GROUP = "overly-permissive"
SERVICES = ["arc-zonal-shift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateZonalAutoshiftConfiguration refuses to enable zonal autoshift for a managed
    resource that has no practice run configuration yet; zonalAutoshiftStatus stays DISABLED,
    and enabling succeeds once a practice run configuration is created (positive control)."""
    arc = ctx.client("arc-zonal-shift")
    lb_arn, _ = _create_nlb_managed_resource(ctx)

    code, message = _error_detail(
        lambda: arc.update_zonal_autoshift_configuration(
            resourceIdentifier=lb_arn, zonalAutoshiftStatus="ENABLED"
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}: {message}"
    expected_message = (
        "Resource does not have a practice run configuration. "
        "Cannot enable zonal autoshift."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect: status is still DISABLED.
    status = arc.get_managed_resource(resourceIdentifier=lb_arn)["zonalAutoshiftStatus"]
    assert status == "DISABLED", f"expected DISABLED after rejected enable, got {status!r}"

    # Positive control: once a practice run configuration exists, enabling succeeds.
    _, outcome_alarm_arn = _create_ok_alarm(ctx)
    arc.create_practice_run_configuration(
        resourceIdentifier=lb_arn,
        outcomeAlarms=[{"type": "CLOUDWATCH", "alarmIdentifier": outcome_alarm_arn}],
    )
    ctx.on_cleanup(lambda: _delete_config_if_present(arc, lb_arn))
    arc.update_zonal_autoshift_configuration(
        resourceIdentifier=lb_arn, zonalAutoshiftStatus="ENABLED"
    )
    enabled_status = arc.get_managed_resource(resourceIdentifier=lb_arn)["zonalAutoshiftStatus"]
    assert enabled_status == "ENABLED", f"expected ENABLED after positive control, got {enabled_status!r}"


# The AccessDeniedException messages real AWS answers GetManagedResource with while ARC has not
# yet registered a load balancer as a managed resource.
_UNREGISTERED_DENIALS = ("is not a managed resource", "Requested resource is not available.")


def _error_detail(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_config_if_present(arc, resource_arn):
    try:
        arc.update_zonal_autoshift_configuration(
            resourceIdentifier=resource_arn, zonalAutoshiftStatus="DISABLED"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
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

    # ARC never auto-registers an NLB unless its zonal-shift integration attribute is
    # explicitly enabled first (docs.aws.amazon.com/r53recovery .../network-load-balancers.html).
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
        except arc.exceptions.ResourceNotFoundException:
            pass
        except arc.exceptions.AccessDeniedException as e:
            # Real AWS answers an NLB that ARC has not yet auto-registered with
            # AccessDeniedException ("is not a managed resource"), not NotFound.
            if not any(m in str(e) for m in _UNREGISTERED_DENIALS):
                raise
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
