"""ecs-service-missing-elb-service-linked-role-negative."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-service-missing-elb-service-linked-role-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudformation", "ecs", "elbv2"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EC2-launch-type CreateService whose role lacks elbv2 permissions fails with
    InvalidParameterException and its exact message, creating no service and registering no target;
    with elbv2 permissions on the role the same service registers one target."""
    # The account-wide AWSServiceRoleForECS service-linked role is persistent shared state, so the
    # check uses the EC2-launch-type `role` parameter of CreateService: that role governs the elbv2
    # RegisterTargets/DeregisterTargets calls ECS makes on the service's behalf, once without and
    # once with elbv2 permissions.
    net = _create_network(ctx)
    try:
        ami_id = _fetch_ecs_optimized_ami(ctx)
    except ClientError as e:
        raise AssertionError(
            f"could not resolve the ECS-optimized AMI via the public SSM parameter ({e}); "
            "ssm:GetParameter permission on /aws/service/ecs/* may be missing in this environment"
        )

    cluster_arn = _create_cluster(ctx)
    cluster_name = cluster_arn.split("/")[-1]
    profile_name = _create_instance_profile(ctx)
    _launch_container_instance(ctx, cluster_name, net["subnet_ids"][0], net["sg_id"], profile_name, ami_id)
    _wait_container_instance_active(ctx, cluster_arn, timeout_s=240)

    td_arn = _register_ec2_task_def(ctx, "web", "public.ecr.aws/docker/library/httpd:latest", 80)
    alb = _create_alb(ctx, net["subnet_ids"], net["sg_id"])
    tg_arn = _create_target_group(ctx, net["vpc_id"], target_type="instance", interval=10)
    _create_listener(ctx, alb["arn"], tg_arn)

    broken_role_arn = _create_service_role(ctx, allow_elb=False)
    rejected_name, code, message = _expect_ec2_service_creation_rejected(
        ctx, cluster_arn, td_arn, tg_arn, "web", 80, broken_role_arn
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}: {message}"
    expected_message = (
        "Unable to assume role and validate the specified targetGroupArn. "
        "Please verify that the ECS service role being passed has the proper permissions."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent, via two independent reads: CreateService itself was rejected, so no service
    # was ever created, and the target group it would have registered against stays empty.
    ecs = ctx.client("ecs")
    live_names = {arn.split("/")[-1] for arn in ecs.list_services(cluster=cluster_arn)["serviceArns"]}
    assert rejected_name not in live_names, f"{rejected_name!r} exists despite its CreateService call being rejected"
    assert _target_health(ctx, tg_arn) == [], "target registered despite CreateService itself being rejected"

    # Positive control: the SAME cluster/task-def/target-group, only the role's permissions differ.
    working_role_arn = _create_service_role(ctx, allow_elb=True)
    _create_ec2_service(ctx, cluster_arn, td_arn, tg_arn, "web", 80, working_role_arn)

    registered = _poll_until(
        lambda: _target_health(ctx, tg_arn),
        lambda ds: len(ds) == 1,
        timeout_s=150, interval_s=10,
    )
    assert len(registered) == 1, "target never registered even after the service role was granted elbv2 permissions"


def _fetch_ecs_optimized_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    value = ssm.get_parameter(Name="/aws/service/ecs/optimized-ami/amazon-linux-2/recommended")["Parameter"]["Value"]
    return json.loads(value)["image_id"]


def _create_instance_profile(ctx) -> str:
    iam = ctx.client("iam")
    role_name = _name(ctx, "ec2-role")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    profile_name = _name(ctx, "ec2-profile")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name))
    return profile_name


def _create_service_role(ctx, allow_elb: bool) -> str:
    iam = ctx.client("iam")
    role_name = _name(ctx, "svc-role-ok" if allow_elb else "svc-role-bad")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if allow_elb:
        policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceRole"
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _poll_until(lambda: _role_visible(ctx, role_name), lambda ok: ok, timeout_s=60, interval_s=5)
    return role_arn


def _role_visible(ctx, role_name) -> bool:
    iam = ctx.client("iam")
    try:
        iam.get_role(RoleName=role_name)
        return True
    except ClientError:
        return False


def _launch_container_instance(ctx, cluster_name, subnet_id, sg_id, profile_name, ami_id) -> str:
    ec2 = ctx.client("ec2")
    user_data = base64.b64encode(f"#!/bin/bash\necho ECS_CLUSTER={cluster_name} >> /etc/ecs/ecs.config\n".encode()).decode()

    def _run():
        return ec2.run_instances(
            ImageId=ami_id, InstanceType="t3.micro", MinCount=1, MaxCount=1,
            IamInstanceProfile={"Name": profile_name},
            NetworkInterfaces=[{
                "DeviceIndex": 0, "SubnetId": subnet_id, "Groups": [sg_id], "AssociatePublicIpAddress": True,
            }],
            UserData=user_data,
            TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": _name(ctx, "ci")}]}],
        )

    deadline = time.monotonic() + 90
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = _run()
            break
        except ClientError as e:
            if e.response["Error"]["Code"] in ("InvalidParameterValue", "InvalidParameter"):
                last_err = e
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise AssertionError(f"run_instances kept failing on IAM instance-profile propagation: {last_err!r}")
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    return instance_id


def _wait_container_instance_active(ctx, cluster_arn, timeout_s=240):
    ecs = ctx.client("ecs")
    arns = _poll_until(
        lambda: ecs.list_container_instances(cluster=cluster_arn, status="ACTIVE")["containerInstanceArns"],
        lambda a: len(a) >= 1,
        timeout_s=timeout_s, interval_s=10,
    )
    return arns[0]


def _register_ec2_task_def(ctx, container_name, image, container_port, command=None) -> str:
    ecs = ctx.client("ecs")
    container = {
        "name": container_name, "image": image, "essential": True, "memory": 128,
        "portMappings": [{"containerPort": container_port, "hostPort": 0, "protocol": "tcp"}],
    }
    if command:
        container["command"] = command
    resp = ecs.register_task_definition(
        family=_name(ctx, "taskdef"), networkMode="bridge",
        requiresCompatibilities=["EC2"], containerDefinitions=[container],
    )
    td_arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_def(ecs, td_arn))
    return td_arn


def _retire_task_def(ecs, arn: str) -> None:
    """Deregister, then delete, one task definition revision, so no INACTIVE revision lingers."""
    ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures") or []
    if failures:
        raise RuntimeError(f"DeleteTaskDefinitions refused {arn}: {failures!r}")


def _create_ec2_service(ctx, cluster_arn, task_def_arn, tg_arn, container_name, container_port, role_arn):
    ecs = ctx.client("ecs")
    name = _name(ctx, "svc")

    # IAM roles are eventually consistent -- ECS's internal "assume role and validate the target
    # group" check can reject a role that get_role() already sees, for up to ~a minute after
    # attach_role_policy. Retry the CreateService call itself on that specific error.
    deadline = time.monotonic() + 90
    svc_arn = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            svc_arn = ecs.create_service(
                cluster=cluster_arn, serviceName=name, taskDefinition=task_def_arn, desiredCount=1,
                launchType="EC2", role=role_arn,
                loadBalancers=[{"targetGroupArn": tg_arn, "containerName": container_name, "containerPort": container_port}],
            )["service"]["serviceArn"]
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterException" and "assume role" in str(e).lower():
                last_err = e
                time.sleep(5)
                continue
            raise
    if svc_arn is None:
        raise AssertionError(f"CreateService kept failing on IAM role propagation: {last_err!r}")

    def _cleanup():
        try:
            ecs.update_service(cluster=cluster_arn, service=name, desiredCount=0)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "ClusterNotFoundException",
                "NamespaceNotFoundException",
                "ServiceNotFoundException",
            ):
                raise
        try:
            ecs.delete_service(cluster=cluster_arn, service=name, force=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "ClusterNotFoundException",
                "ServiceNotFoundException",
            ):
                raise

    ctx.on_cleanup(_cleanup)
    return {"arn": svc_arn, "name": name}


def _expect_ec2_service_creation_rejected(ctx, cluster_arn, task_def_arn, tg_arn, container_name, container_port, role_arn):
    """A role with no elbv2 permissions can never pass ECS's synchronous assume-and-validate
    check on CreateService; real AWS refuses the call itself with InvalidParameterException
    rather than accepting it and silently never registering targets. Retry only to ride out
    early IAM-visibility noise -- the rejection itself does not resolve, because the role never
    gains the permission it lacks."""
    ecs = ctx.client("ecs")
    name = _name(ctx, "svc-rejected")
    deadline = time.monotonic() + 90
    last_code, last_message = None, None
    while time.monotonic() < deadline:
        try:
            ecs.create_service(
                cluster=cluster_arn, serviceName=name, taskDefinition=task_def_arn, desiredCount=1,
                launchType="EC2", role=role_arn,
                loadBalancers=[{"targetGroupArn": tg_arn, "containerName": container_name, "containerPort": container_port}],
            )
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            last_message = e.response["Error"].get("Message", "")
            if last_code == "InvalidParameterException" and "targetgrouparn" in last_message.lower():
                return name, last_code, last_message
            time.sleep(5)
            continue
        # CreateService succeeded outright -- clean up what it made and fail loudly rather than
        # passing quietly on a role that turned out not to be as restricted as it was built to be.
        ctx.on_cleanup(lambda: ecs.update_service(cluster=cluster_arn, service=name, desiredCount=0))
        ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_arn, service=name, force=True))
        raise AssertionError(
            f"CreateService succeeded for {name!r} despite the role lacking elbv2 permissions; "
            "expected a synchronous InvalidParameterException"
        )
    raise AssertionError(
        f"CreateService never settled into the expected InvalidParameterException within 90s; "
        f"last seen: {last_code} {last_message!r}"
    )


def _delete_sg_when_free(ec2, group_id, timeout_s=300):
    """Delete a security group, retrying while ENIs of a terminating instance or ALB still hold it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=group_id)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() > deadline:
                raise
        time.sleep(10)


_PREFIX = "sim2real-ecsalb-"


def _name(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_network(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"][0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]
    sg_id = ec2.create_security_group(
        GroupName=_name(ctx, "sg"), Description="sim2real ecs-alb shared sg", VpcId=vpc_id
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg_when_free(ec2, sg_id))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535, "UserIdGroupPairs": [{"GroupId": sg_id}]}],
    )
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sg_id}


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    arn = ecs.create_cluster(clusterName=_name(ctx, "cluster"))["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=arn))
    return arn


def _create_alb(ctx, subnet_ids, sg_id):
    elbv2 = ctx.client("elbv2")
    resp = elbv2.create_load_balancer(
        Name=_name(ctx, "alb"), Subnets=subnet_ids, SecurityGroups=[sg_id],
        Scheme="internet-facing", Type="application", IpAddressType="ipv4",
    )
    alb_arn = resp["LoadBalancers"][0]["LoadBalancerArn"]
    alb_dns = resp["LoadBalancers"][0]["DNSName"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=alb_arn))
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda s: s == "active",
        timeout_s=240, interval_s=10,
    )
    return {"arn": alb_arn, "dns": alb_dns}


def _create_target_group(ctx, vpc_id, port=80, target_type="ip", health_check_path="/",
                          interval=10, healthy_threshold=2, unhealthy_threshold=2,
                          deregistration_delay=None):
    elbv2 = ctx.client("elbv2")
    timeout = max(2, min(interval - 1, 5))
    tg_arn = elbv2.create_target_group(
        Name=_name(ctx, "tg"), Protocol="HTTP", Port=port, VpcId=vpc_id, TargetType=target_type,
        HealthCheckProtocol="HTTP", HealthCheckPath=health_check_path,
        HealthCheckIntervalSeconds=interval, HealthCheckTimeoutSeconds=timeout,
        HealthyThresholdCount=healthy_threshold, UnhealthyThresholdCount=unhealthy_threshold,
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))
    if deregistration_delay is not None:
        elbv2.modify_target_group_attributes(
            TargetGroupArn=tg_arn,
            Attributes=[{"Key": "deregistration_delay.timeout_seconds", "Value": str(deregistration_delay)}],
        )
    return tg_arn


def _create_listener(ctx, alb_arn, tg_arn, port=80):
    elbv2 = ctx.client("elbv2")
    listener_arn = elbv2.create_listener(
        LoadBalancerArn=alb_arn, Protocol="HTTP", Port=port,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    return listener_arn


def _target_health(ctx, tg_arn):
    elbv2 = ctx.client("elbv2")
    return elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
