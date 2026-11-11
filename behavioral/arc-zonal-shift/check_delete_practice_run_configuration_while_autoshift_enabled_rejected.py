"""delete-practice-run-configuration-while-autoshift-enabled-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-practice-run-configuration-while-autoshift-enabled-rejected"
GROUP = "errors"
SERVICES = ["arc-zonal-shift"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePracticeRunConfiguration is rejected while zonal autoshift is still ENABLED for
    the resource; the configuration remains in place, and deleting succeeds once autoshift is
    disabled first (positive control)."""
    arc = ctx.client("arc-zonal-shift")
    lb_arn, _ = _create_nlb_managed_resource(ctx)
    _, outcome_alarm_arn = _create_ok_alarm(ctx)

    arc.create_practice_run_configuration(
        resourceIdentifier=lb_arn,
        outcomeAlarms=[{"type": "CLOUDWATCH", "alarmIdentifier": outcome_alarm_arn}],
    )
    ctx.on_cleanup(lambda: _delete_config_if_present(arc, lb_arn))
    arc.update_zonal_autoshift_configuration(
        resourceIdentifier=lb_arn, zonalAutoshiftStatus="ENABLED"
    )

    code, message = _error_detail(lambda: arc.delete_practice_run_configuration(resourceIdentifier=lb_arn))
    assert code == "ConflictException", f"expected ConflictException, got {code!r}: {message}"
    expected_message = (
        "Zonal autoshift is ENABLED. Cannot delete a practice "
        "run configuration for the requested resource."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect: the configuration is still present.
    resource = arc.get_managed_resource(resourceIdentifier=lb_arn)
    assert resource.get("practiceRunConfiguration") is not None

    # Positive control: disabling autoshift first allows the delete to succeed.
    arc.update_zonal_autoshift_configuration(
        resourceIdentifier=lb_arn, zonalAutoshiftStatus="DISABLED"
    )
    arc.delete_practice_run_configuration(resourceIdentifier=lb_arn)
    resource_after = arc.get_managed_resource(resourceIdentifier=lb_arn)
    assert resource_after.get("practiceRunConfiguration") is None


# ===== helpers =====
# The AccessDeniedException messages real AWS answers GetManagedResource with while ARC has not
# yet registered a load balancer as a managed resource.
_UNREGISTERED_DENIALS = ("is not a managed resource", "Requested resource is not available.")


def _error_detail(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because
    accepting a call AWS refuses is a different failure from answering it with the wrong code."""
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


def _tag_spec(resource_type, name):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "sim2real", "Value": name}]}]


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
        Tags=[{"Key": "sim2real", "Value": name}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))
    arn = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]["AlarmArn"]
    return name, arn


def _adopt_or_create_vpc(ctx):
    """Adopt the run's shared network if it spans >= 2 AZs; otherwise create a dedicated one.

    Never depends on an ambient shared network being present -- a freshly provisioned account may
    not have one -- but adopts one when it exists rather than always creating a fresh VPC, which
    needlessly spends the account's (low, shared-account-contended) VPC quota."""
    ec2 = ctx.client("ec2")
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return [by_az[az] for az in sorted(by_az)[:2]]

    name = ctx.unique_name("sim2real-arczs-")
    azs = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    )[:2]
    if len(azs) < 2:
        raise AssertionError(f"region {ctx.region} does not have 2 available Availability Zones")

    vpc_id = ec2.create_vpc(CidrBlock="10.190.0.0/16", TagSpecifications=_tag_spec("vpc", name))[
        "Vpc"
    ]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.190.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=_tag_spec("subnet", name),
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _nlb_exists(elbv2, lb_arn):
    try:
        elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise
        return False


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)
        result = probe()
    return result


def _create_nlb_managed_resource(ctx):
    """Provision an internal NLB across 2 AZs (adopting the default VPC's subnets when present,
    otherwise a dedicated VPC), opt it in to ARC zonal shift, and wait for ARC to register it as
    a managed resource. Returns (load_balancer_arn, away_from_az_id).

    A load balancer is NEVER auto-discovered by ARC merely by spanning 2 AZs -- measured on real
    AWS, a bare NLB with no opt-in never became a managed resource inside a 15-minute poll. Per
    AWS docs (r53recovery: "Network Load Balancers"), zonal shift integration is an explicit
    opt-in via ``elbv2:ModifyLoadBalancerAttributes`` (``zonal_shift.config.enabled=true``)."""
    elbv2 = ctx.client("elbv2")
    arc = ctx.client("arc-zonal-shift")
    tag = ctx.unique_name("sim2real-arczs-")
    subnet_ids = _adopt_or_create_vpc(ctx)

    name = ctx.unique_name("sim2realarczs")[:32].strip("-")
    lb = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        Scheme="internal",
        Type="network",
        IpAddressType="ipv4",
        Tags=[{"Key": "sim2real", "Value": tag}],
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]

    def _cleanup_nlb():
        try:
            elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                raise
            return
        _poll_until(
            lambda: _nlb_exists(elbv2, lb_arn),
            lambda exists: not exists,
            timeout_s=180.0,
            interval_s=10.0,
        )

    ctx.on_cleanup(_cleanup_nlb)
    elbv2.get_waiter("load_balancer_available").wait(
        LoadBalancerArns=[lb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )

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
            # Real AWS answers a not-yet-discovered resource with AccessDeniedException
            # ("... is not a managed resource for account ID ..."), not
            # ResourceNotFoundException. Any other AccessDenied is a real permissions problem
            # and must not be swallowed for the full 900s poll window.
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


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes: a load balancer deletes
# asynchronously, so an immediate DeleteSubnet / DeleteVpc fails with DependencyViolation. Wait (bounded)
# for the ENIs, retry DependencyViolation in the same window, then raise naming the ENIs still attached.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
