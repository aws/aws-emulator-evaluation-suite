"""placement-constraint-memberof-attribute-filters-candidate-instances."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "placement-constraint-memberof-attribute-filters-candidate-instances"
GROUP = "task-lifecycle"
SERVICES = ["ecs"]

_ATTR_NAME = "sim2real-placement-slot"
_ATTR_VALUE = "alpha"
# The whole point of the constraint: an expression over a CUSTOM attribute, evaluated by ECS's
# cluster query language against the candidate container instances.
_EXPRESSION = f"attribute:{_ATTR_NAME} == {_ATTR_VALUE}"
_ATTR_SCHEDULER_S = 120.0


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A memberOf constraint naming an attribute no instance carries places nothing;
    once PutAttributes grants it, the identical RunTask places the task on that instance.
    """
    ecs = ctx.client("ecs")

    subnet_id, sg_id = _public_network(ctx)
    cluster = _create_cluster(ctx, ecs)
    ci_arn = _launch_container_instance(ctx, ecs, cluster, subnet_id, sg_id)

    # An EC2-launch-type (bridge) task definition: placement constraints are NOT supported on
    # Fargate, so the launch type is load-bearing, not incidental.
    family = ctx.unique_name("sim2real-behav-ecs-placement-")
    td_arn = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "cpu": 128,
                "memory": 128,
                "command": ["sh", "-c", "sleep 900"],
            }
        ],
        networkMode="bridge",
        requiresCompatibilities=["EC2"],
        tags=_ecs_tags(),
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.delete_task_definitions(taskDefinitions=[td_arn])))
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.deregister_task_definition(taskDefinition=td_arn)))

    # Positive control: an unconstrained RunTask places on the one instance.
    control = ecs.run_task(
        cluster=cluster, taskDefinition=td_arn, launchType="EC2", count=1, tags=_ecs_tags()
    )
    assert not control.get("failures"), (
        "the UNCONSTRAINED positive control must place: a failure here means the cluster, the task "
        f"definition or the agent is broken and nothing below is evidence — {control.get('failures')!r}"
    )
    control_task = control["tasks"][0]["taskArn"]
    ctx.on_cleanup(
        lambda: _swallow(
            lambda: ecs.stop_task(cluster=cluster, task=control_task, reason="behavioral-cleanup")
        )
    )
    placed_on = ecs.describe_tasks(cluster=cluster, tasks=[control_task])["tasks"][0].get(
        "containerInstanceArn"
    )
    assert placed_on == ci_arn, (
        f"the unconstrained control task must be placed on the one registered container instance "
        f"{ci_arn!r}, got {placed_on!r}"
    )

    ecs.stop_task(cluster=cluster, task=control_task, reason="freeing the control task's capacity")
    _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster, tasks=[control_task])["tasks"][0]["lastStatus"],
        lambda s: s == "STOPPED",
        timeout_s=_budget_s(ctx, 300),
        interval_s=1,
        description="the control task releases its reservation so the constrained attempts below "
        "cannot fail for capacity reasons",
        ctx=ctx,
    )

    before = _task_arn_set(ecs, cluster)

    refused = ecs.run_task(
        cluster=cluster,
        taskDefinition=td_arn,
        launchType="EC2",
        count=1,
        placementConstraints=[{"type": "memberOf", "expression": _EXPRESSION}],
        tags=_ecs_tags(),
    )
    assert refused["tasks"] == [], (
        f"ECS must place NO task when the memberOf expression {_EXPRESSION!r} matches no container "
        f"instance, but it returned {len(refused['tasks'])} task(s): "
        f"{[t.get('taskArn') for t in refused['tasks']]!r}"
    )
    failures = refused["failures"]
    assert len(failures) == 1, (
        f"expected exactly one failures[] entry describing the unplaceable task, got "
        f"{len(failures)}: {failures!r}"
    )
    # The reason is the full sentence, not the short code "ATTRIBUTE" used by other refusals.
    reason = failures[0].get("reason")
    assert reason == "MemberOf placement constraint unsatisfied.", (
        "an unsatisfied memberOf placement constraint must be reported with this exact reason "
        "text (the scheduler evaluated the expression and found no candidate), not as a capacity "
        f"or generic failure: expected 'MemberOf placement constraint unsatisfied.', got {reason!r} "
        f"(full entry {failures[0]!r})"
    )
    # The failures[] entry names the CONTAINER INSTANCE the scheduler rejected, not the task
    # (no task exists). failures[].arn is the SHORT ARN (no cluster segment) while
    # DescribeContainerInstances reports the long form, so compare on the trailing id.
    failure_ci_id = (failures[0].get("arn") or "").rsplit("/", 1)[-1]
    ci_id = ci_arn.rsplit("/", 1)[-1]
    assert failure_ci_id == ci_id, (
        f"the failures[] entry's arn must identify the container instance the constraint was "
        f"evaluated against, expected id {ci_id!r} (from {ci_arn!r}), got "
        f"{failures[0].get('arn')!r}"
    )

    # The claim is "nothing NEW was created", asserted as a set difference rather than set equality:
    # the just-stopped control task may still be draining out of ListTasks between the two reads, and
    # equality would turn that into a spurious failure while proving nothing extra.
    after_refusal = _task_arn_set(ecs, cluster)
    created = after_refusal - before
    assert created == set(), (
        f"the refused RunTask must have created no task, but ListTasks gained {sorted(created)!r} "
        f"(before={sorted(before)!r}, after={sorted(after_refusal)!r})"
    )

    ecs.put_attributes(
        cluster=cluster,
        attributes=[{"name": _ATTR_NAME, "targetId": ci_arn, "value": _ATTR_VALUE}],
    )
    ctx.on_cleanup(
        lambda: _swallow(
            lambda: ecs.delete_attributes(
                cluster=cluster, attributes=[{"name": _ATTR_NAME, "targetId": ci_arn}]
            )
        )
    )
    granted = _poll_until(
        lambda: {
            (a["name"], a.get("value"))
            for a in ecs.list_attributes(cluster=cluster, targetType="container-instance")[
                "attributes"
            ]
            if a.get("targetId") == ci_arn
        },
        lambda pairs: (_ATTR_NAME, _ATTR_VALUE) in pairs,
        timeout_s=_budget_s(ctx, 60),
        interval_s=1,
        description=f"PutAttributes({_ATTR_NAME}={_ATTR_VALUE}) becomes visible to ListAttributes",
        ctx=ctx,
    )
    assert (_ATTR_NAME, _ATTR_VALUE) in granted, (
        f"expected the granted attribute {_ATTR_NAME}={_ATTR_VALUE} on {ci_arn}, saw {granted!r}"
    )

    # Retry RunTask itself rather than sleeping: the attribute is visible to ListAttributes above,
    # but the scheduler's candidate view may trail it by a bounded amount. A retry whose success
    # condition is "no failures" cannot mask a target that never places, because it raises.
    accepted = _poll_until(
        lambda: ecs.run_task(
            cluster=cluster,
            taskDefinition=td_arn,
            launchType="EC2",
            count=1,
            placementConstraints=[{"type": "memberOf", "expression": _EXPRESSION}],
            tags=_ecs_tags(),
        ),
        lambda r: not r.get("failures"),
        timeout_s=_budget_s(ctx, _ATTR_SCHEDULER_S),
        interval_s=2,
        description="the granted attribute makes the IDENTICAL constrained RunTask placeable",
        ctx=ctx,
    )
    constrained_task = accepted["tasks"][0]["taskArn"]
    ctx.on_cleanup(
        lambda: _swallow(
            lambda: ecs.stop_task(
                cluster=cluster, task=constrained_task, reason="behavioral-cleanup"
            )
        )
    )
    described = ecs.describe_tasks(cluster=cluster, tasks=[constrained_task])["tasks"][0]
    assert described.get("containerInstanceArn") == ci_arn, (
        "the constrained task must be placed on the container instance that now carries the "
        f"attribute: expected {ci_arn!r}, got {described.get('containerInstanceArn')!r}"
    )
    assert described["taskArn"] not in before, (
        f"DescribeTasks returned a pre-existing task {described['taskArn']!r} rather than the "
        "newly placed one"
    )


# ===== helpers =====

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_ECS_INSTANCE_MANAGED_POLICY = (
    "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
)


def _ecs_tags() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _ec2_tags() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _swallow(fn) -> None:
    """Run fn(), swallowing any exception. Teardown ONLY — never on an assertion path."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("ClusterNotFoundException", "Gateway.NotAttached", "InvalidInstanceID.NotFound", "InvalidInternetGatewayID.NotFound", "NoSuchEntity", "TargetNotFoundException")
            and not (err["Code"] == "ClientException" and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted")))
        ):
            raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s, interval_s, description, ctx=None):
    """Bounded retry that RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}; last observed {last!r}"
    )


def _task_arn_set(ecs, cluster) -> set[str]:
    """Every task the cluster knows about in a non-terminal desired state."""
    arns: set[str] = set()
    for desired in ("RUNNING", "PENDING"):
        token = None
        while True:
            kwargs = {"cluster": cluster, "desiredStatus": desired}
            if token:
                kwargs["nextToken"] = token
            resp = ecs.list_tasks(**kwargs)
            arns.update(resp["taskArns"])
            token = resp.get("nextToken")
            if not token:
                break
    return arns


def _create_cluster(ctx, ecs) -> str:
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name, tags=_ecs_tags())
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.delete_cluster(cluster=name)))
    return name


def _public_network(ctx):
    """A dedicated VPC with one public subnet, an IGW and a default route.

    An account may lack a usable default VPC; the ECS agent needs egress to reach ECS and ECR.
    """
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.199.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _ec2_tags()}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.199.0.0/25",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _ec2_tags()}],
    )["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _ec2_tags()}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
        "RouteTables"
    ][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    sg_id = next(
        sg["GroupId"]
        for sg in ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
            "SecurityGroups"
        ]
        if sg["GroupName"] == "default"
    )

    def _teardown_network():
        # The instance cleanup registered LATER runs FIRST under LIFO and has already asked EC2 to
        # terminate; its ENI blocks subnet deletion until it is really gone, so wait it out on a
        # bounded deadline rather than sleeping a fixed amount.
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            if not ec2.describe_network_interfaces(
                Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
            ).get("NetworkInterfaces", []):
                break
            time.sleep(2)
        while time.monotonic() < deadline:
            try:
                ec2.delete_subnet(SubnetId=subnet_id)
                break
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "InvalidSubnetID.NotFound":
                    break
                time.sleep(2)
        _swallow(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id))
        _swallow(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))
        while time.monotonic() < deadline:
            try:
                ec2.delete_vpc(VpcId=vpc_id)
                return
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "InvalidVpcID.NotFound":
                    return
                time.sleep(2)
        raise RuntimeError(
            f"vpc {vpc_id} / subnet {subnet_id} not deleted within the teardown deadline"
        )

    ctx.on_cleanup(_teardown_network)
    return subnet_id, sg_id


def _instance_profile(ctx) -> str:
    """An IAM role + same-named instance profile carrying the ECS container-instance policy."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-ecsInstanceRole-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role, AssumeRolePolicyDocument=json.dumps(trust), Tags=_ec2_tags()
    )
    ctx.on_cleanup(lambda: _swallow(lambda: iam.delete_role(RoleName=role)))
    iam.attach_role_policy(RoleName=role, PolicyArn=_ECS_INSTANCE_MANAGED_POLICY)
    ctx.on_cleanup(
        lambda: _swallow(
            lambda: iam.detach_role_policy(RoleName=role, PolicyArn=_ECS_INSTANCE_MANAGED_POLICY)
        )
    )
    iam.create_instance_profile(InstanceProfileName=role, Tags=_ec2_tags())
    ctx.on_cleanup(lambda: _swallow(lambda: iam.delete_instance_profile(InstanceProfileName=role)))
    iam.add_role_to_instance_profile(InstanceProfileName=role, RoleName=role)
    ctx.on_cleanup(
        lambda: _swallow(
            lambda: iam.remove_role_from_instance_profile(
                InstanceProfileName=role, RoleName=role
            )
        )
    )
    return iam.get_instance_profile(InstanceProfileName=role)["InstanceProfile"]["Arn"]


def _launch_container_instance(ctx, ecs, cluster, subnet_id, sg_id) -> str:
    """Launch one EC2 host that self-registers as an ECS container instance via the real agent.

    RegisterContainerInstance requires a genuine signed instance-identity document.
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami_id = ssm.get_parameter(
        Name="/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id"
    )["Parameter"]["Value"]
    profile_arn = _instance_profile(ctx)
    user_data = f"#!/bin/bash\necho ECS_CLUSTER={cluster} >> /etc/ecs/ecs.config\n"

    # The instance profile was just created; EC2's view of it lags IAM by a bounded amount, so
    # retry RunInstances itself rather than sleeping. Raises if it never becomes launchable.
    instance_id = _poll_until(
        lambda: _try_run_instances(
            ec2, ami_id, profile_arn, subnet_id, sg_id, user_data, ctx
        ),
        lambda r: isinstance(r, str),
        timeout_s=_budget_s(ctx, 180),
        interval_s=2,
        description="the freshly created instance profile becomes usable by RunInstances",
        ctx=ctx,
    )
    ctx.on_cleanup(lambda: _swallow(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))

    def _registered():
        arns = ecs.list_container_instances(cluster=cluster).get("containerInstanceArns", [])
        if not arns:
            return None
        for ci in ecs.describe_container_instances(
            cluster=cluster, containerInstances=arns
        )["containerInstances"]:
            if ci.get("ec2InstanceId") == instance_id and ci.get("status") == "ACTIVE":
                return ci
        return None

    ci = _poll_until(
        _registered,
        lambda x: x is not None,
        timeout_s=_budget_s(ctx, 420),
        interval_s=2,
        description=f"EC2 instance {instance_id} registers as an ACTIVE ECS container instance",
        ctx=ctx,
    )
    ci_arn = ci["containerInstanceArn"]
    ctx.on_cleanup(
        lambda: _swallow(
            lambda: ecs.deregister_container_instance(
                cluster=cluster, containerInstance=ci_arn, force=True
            )
        )
    )
    return ci_arn


def _try_run_instances(ec2, ami_id, profile_arn, subnet_id, sg_id, user_data, ctx):
    """RunInstances once; return the instance id on success or the ClientError on failure."""
    try:
        return ec2.run_instances(
            ImageId=ami_id,
            InstanceType="t3.micro",
            MinCount=1,
            MaxCount=1,
            IamInstanceProfile={"Arn": profile_arn},
            SubnetId=subnet_id,
            SecurityGroupIds=[sg_id],
            UserData=base64.b64encode(user_data.encode()).decode(),
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": _ec2_tags()
                    + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-ecs-ci-")}],
                }
            ],
        )["Instances"][0]["InstanceId"]
    except ClientError as exc:
        return exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
