"""asp-predictive-forecast-without-history-has-no-datapoints."""
from __future__ import annotations

import datetime as dt
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asp-predictive-forecast-without-history-has-no-datapoints"
GROUP = 'predictive-scaling-forecast'
SERVICES = ['autoscaling-plans']

_NS = 'autoscaling'
_DIM = 'autoscaling:autoScalingGroup:DesiredCapacity'
_AMI_PARAM = ('/aws/service/ami-amazon-linux-latest/'
              'al2023-ami-kernel-default-x86_64')
_INSTANCE_TYPE = 't3.micro'
_TYPES = ('LoadForecast', 'CapacityForecast', 'ScheduledActionMinCapacity',
          'ScheduledActionMaxCapacity')


def _ignore_absent(fn, *codes):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in codes:
            raise


def _delete_plan(asp, name, version, timeout=300.0):
    deadline = time.time() + timeout
    while True:
        try:
            asp.delete_scaling_plan(ScalingPlanName=name,
                                    ScalingPlanVersion=version)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ObjectNotFoundException":
                return
            if code != "ConcurrentUpdateException" or time.time() > deadline:
                raise
            time.sleep(6)


def _delete_group(asg, name, timeout=300.0):
    """Force-delete the group and WAIT for it to go, so the subnet can follow."""
    _ignore_absent(lambda: asg.delete_auto_scaling_group(
        AutoScalingGroupName=name, ForceDelete=True), "ValidationError")
    deadline = time.time() + timeout
    while time.time() < deadline:
        groups = asg.describe_auto_scaling_groups(
            AutoScalingGroupNames=[name])["AutoScalingGroups"]
        if not groups:
            return
        time.sleep(5)
    raise AssertionError(f"auto scaling group {name!r} did not disappear within "
                         f"{timeout}s of a force delete")


def _await_plan(asp, name, timeout=300.0):
    """Poll until the plan leaves CreationInProgress; return it."""
    deadline = time.time() + timeout
    seen = "<never visible>"
    while time.time() < deadline:
        plans = asp.describe_scaling_plans(
            ScalingPlanNames=[name])["ScalingPlans"]
        if plans:
            seen = plans[0]["StatusCode"]
            if seen != "CreationInProgress":
                return plans[0]
        time.sleep(3)
    raise AssertionError(
        f"scaling plan {name!r} never left CreationInProgress within {timeout}s; "
        f"last status was {seen!r}")


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A ForecastOnly predictive scaling plan over a new, empty Auto Scaling group becomes Active
    and every ForecastDataType read answers 200 with no datapoints: the cold-start forecast is
    absent, not an error and not a fabricated series."""
    asp = ctx.client("autoscaling-plans")
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    ami = ssm.get_parameter(Name=_AMI_PARAM)["Parameter"]["Value"]
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}],
    )["InstanceTypeOfferings"]}
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert zones, (
        f"no available availability zone in {ctx.region} offers "
        f"{_INSTANCE_TYPE}; a predictive scaling plan needs a launchable group")

    tag = ctx.unique_name("sim2real-behav-asp-")
    vpc = ec2.create_vpc(
        CidrBlock="10.71.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [
            {"Key": "sim2real-asp", "Value": tag},
            {"Key": "Name", "Value": tag}]}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _ignore_absent(
        lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc), "InvalidVpcID.NotFound"))
    subnet = ec2.create_subnet(
        VpcId=vpc, CidrBlock="10.71.1.0/24", AvailabilityZone=zones[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [
            {"Key": "sim2real-asp", "Value": tag}]}])["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _ignore_absent(
        lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet), "InvalidSubnetID.NotFound"))

    template = ctx.unique_name("sim2real-behav-asp-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=template,
        LaunchTemplateData={"ImageId": ami, "InstanceType": _INSTANCE_TYPE},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [
            {"Key": "sim2real-asp", "Value": tag}]}])
    ctx.on_cleanup(lambda: _ignore_absent(
        lambda: ec2.delete_launch_template(LaunchTemplateName=template),
        "InvalidLaunchTemplateName.NotFoundException"))

    group = ctx.unique_name("sim2real-behav-asp-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group,
        LaunchTemplate={"LaunchTemplateName": template, "Version": "$Latest"},
        MinSize=0, MaxSize=1, DesiredCapacity=0,
        VPCZoneIdentifier=subnet,
        Tags=[{"Key": "sim2real-asp", "Value": tag, "PropagateAtLaunch": False}])
    ctx.on_cleanup(lambda: _delete_group(asg, group))

    plan = ctx.unique_name("sim2real-behav-asp-plan-")
    ctx.on_cleanup(lambda: _delete_plan(asp, plan, 1))
    created = asp.create_scaling_plan(
        ScalingPlanName=plan,
        ApplicationSource={"TagFilters": [{"Key": "sim2real-asp",
                                           "Values": [tag]}]},
        ScalingInstructions=[{
            "ServiceNamespace": _NS,
            "ResourceId": f"autoScalingGroup/{group}",
            "ScalableDimension": _DIM,
            "MinCapacity": 0,
            "MaxCapacity": 1,
            "TargetTrackingConfigurations": [{
                "PredefinedScalingMetricSpecification": {
                    "PredefinedScalingMetricType": "ASGAverageCPUUtilization"},
                "TargetValue": 50.0}],
            "PredefinedLoadMetricSpecification": {
                "PredefinedLoadMetricType": "ASGTotalCPUUtilization"},
            "PredictiveScalingMode": "ForecastOnly",
            "DisableDynamicScaling": True,
        }],
    )
    assert created["ScalingPlanVersion"] == 1, \
        f"expected a first version of 1, got {created['ScalingPlanVersion']!r}"

    settled = _await_plan(asp, plan)
    assert settled["StatusCode"] == "Active", (
        f"expected the predictive plan to reach Active, got "
        f"{settled['StatusCode']!r}: {settled.get('StatusMessage')!r}")
    instruction = settled["ScalingInstructions"][0]
    assert instruction["PredictiveScalingMode"] == "ForecastOnly", (
        f"expected PredictiveScalingMode ForecastOnly to read back, got "
        f"{instruction.get('PredictiveScalingMode')!r}")
    assert instruction["DisableDynamicScaling"] is True, (
        f"expected DisableDynamicScaling true to read back, got "
        f"{instruction.get('DisableDynamicScaling')!r}")
    assert instruction["PredefinedLoadMetricSpecification"][
        "PredefinedLoadMetricType"] == "ASGTotalCPUUtilization", (
        f"expected the load metric to read back, got "
        f"{instruction.get('PredefinedLoadMetricSpecification')!r}")

    # ForecastOnly plus DisableDynamicScaling means nothing is ever launched.
    live = asg.describe_auto_scaling_groups(
        AutoScalingGroupNames=[group])["AutoScalingGroups"][0]
    assert live["DesiredCapacity"] == 0, (
        f"the ForecastOnly plan moved DesiredCapacity to "
        f"{live['DesiredCapacity']!r}; a forecast-only plan must not scale")
    assert live["Instances"] == [], (
        f"the ForecastOnly plan launched instances: "
        f"{[i['InstanceId'] for i in live['Instances']]!r}")

    # every forecast type: 200, and empty, because the group has no history
    now = dt.datetime.now(dt.timezone.utc).replace(minute=0, second=0,
                                                   microsecond=0)
    for data_type in _TYPES:
        got = asp.get_scaling_plan_resource_forecast_data(
            ScalingPlanName=plan, ScalingPlanVersion=1, ServiceNamespace=_NS,
            ResourceId=f"autoScalingGroup/{group}", ScalableDimension=_DIM,
            ForecastDataType=data_type, StartTime=now,
            EndTime=now + dt.timedelta(days=1))
        assert got["Datapoints"] == [], (
            f"{data_type}: a group created moments ago has no metric history, so "
            f"the forecast must be empty; got {got['Datapoints']!r}")


# Network teardown: an async-deleted resource's ENIs can hold the subnet / security group / VPC
# (DependencyViolation), so wait for them and retry that code to one shared deadline, then raise
# naming the ENIs still attached; every other error propagates.
_NET_TEARDOWN_S = 42.0
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
