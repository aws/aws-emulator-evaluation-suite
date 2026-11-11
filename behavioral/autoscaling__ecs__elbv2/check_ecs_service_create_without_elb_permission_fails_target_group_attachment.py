"""ecs-service-create-without-elb-permission-fails-target-group-attachment."""
from __future__ import annotations

import ipaddress
import json
import time

from behavioral_harness import tags

CHECK = "ecs-service-create-without-elb-permission-fails-target-group-attachment"
GROUP = "permission-boundary"
SERVICES = ["autoscaling", "ecs", "elbv2"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Attaching an ECS task's ENI as an ALB target needs elasticloadbalancing:RegisterTargets on the
    target group: a role without it gets AccessDeniedException and no target, a role with it registers."""
    ctx.client("ecs")
    elbv2 = ctx.client("elbv2")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    vpc_id, subnet_ids = _default_vpc_subnets(ctx)

    # Ground the target group in an actual ECS awsvpc task-definition context: this
    # is the container/port an ECS service attaching to this target group would use.
    task_def_arn = _register_task_def(ctx, container_name="web", container_port=80)
    assert task_def_arn, "register_task_definition returned no taskDefinitionArn"

    tg_arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-tg-"),
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="ip",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))

    _ensure_elb_service_linked_role(iam)


    subnet = ec2.describe_subnets(SubnetIds=[subnet_ids[0]])["Subnets"][0]
    candidate_ip = str(ipaddress.ip_network(subnet["CidrBlock"]).network_address + 10)

    # sanity: root/ambient creds can register this exact IP against this exact target
    # group (isolates target-group/IP setup issues from anything role-specific below).
    # A target group's first RegisterTargets in a fresh account can transiently surface
    # as InternalFailure while the AWSServiceRoleForElasticLoadBalancing service-linked
    # role finishes propagating — give this generous headroom.
    _wait_for_success(
        lambda: elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": candidate_ip, "Port": 80}]),
        timeout_s=240,
        interval_s=10,
    )
    sanity_targets = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    assert len(sanity_targets) == 1, f"expected 1 registered target after the sanity RegisterTargets, got {sanity_targets!r}"
    elbv2.deregister_targets(TargetGroupArn=tg_arn, Targets=[{"Id": candidate_ip, "Port": 80}])


    account_id = sts.get_caller_identity()["Account"]
    root_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "sts:AssumeRole"}
            ],
        }
    )

    # -- role WITHOUT elasticloadbalancing permission (explicit Deny, not merely absent --
    # some backends surface a bare implicit-deny with zero attached policies as a
    # transient InternalFailure instead of AccessDenied; an explicit Deny statement is
    # the unambiguous way to exercise the same boundary) --
    deny_role_name = ctx.unique_name("sim2real-noelbperm-")
    iam.create_role(
        RoleName=deny_role_name,
        AssumeRolePolicyDocument=root_trust,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=deny_role_name))
    deny_role_arn = iam.get_role(RoleName=deny_role_name)["Role"]["Arn"]
    deny_policy_name = ctx.unique_name("sim2real-noelbperm-policy-")
    iam.put_role_policy(
        RoleName=deny_role_name,
        PolicyName=deny_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": ["elasticloadbalancing:RegisterTargets"],
                        "Resource": "*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["elasticloadbalancing:DescribeTargetHealth"],
                        "Resource": "*",
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=deny_role_name, PolicyName=deny_policy_name))


    # -- role WITH elasticloadbalancing:RegisterTargets permission (positive control) --
    allow_role_name = ctx.unique_name("sim2real-elbperm-")
    iam.create_role(
        RoleName=allow_role_name,
        AssumeRolePolicyDocument=root_trust,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=allow_role_name))
    allow_role_arn = iam.get_role(RoleName=allow_role_name)["Role"]["Arn"]
    allow_policy_name = ctx.unique_name("sim2real-elbperm-policy-")
    iam.put_role_policy(
        RoleName=allow_role_name,
        PolicyName=allow_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["elasticloadbalancing:RegisterTargets", "elasticloadbalancing:DescribeTargetHealth"],
                        "Resource": tg_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=allow_role_name, PolicyName=allow_policy_name))

    _wait_role_assumable(sts, deny_role_arn, timeout_s=60)
    _wait_role_assumable(sts, allow_role_arn, timeout_s=60)

    # --- positive control FIRST: role scoped with the permission succeeds ---
    # (establishes that register_targets against this target group/IP works via an
    # assumed-role session at all, before we assert on the negative path)
    allow_creds = sts.assume_role(RoleArn=allow_role_arn, RoleSessionName="sim2real-allow")["Credentials"]
    allow_elbv2 = _client_with_creds(ctx, "elbv2", allow_creds)
    _wait_for_success(
        lambda: allow_elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": candidate_ip, "Port": 80}]),
        timeout_s=60,
    )

    targets_after_allowed = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    assert len(targets_after_allowed) == 1, (
        f"expected exactly 1 target after the scoped-allow role registered it, got {targets_after_allowed!r}"
    )
    assert targets_after_allowed[0]["Target"]["Id"] == candidate_ip, (
        f"expected the registered target id to be {candidate_ip!r}, got {targets_after_allowed[0]['Target']['Id']!r}"
    )
    elbv2.deregister_targets(TargetGroupArn=tg_arn, Targets=[{"Id": candidate_ip, "Port": 80}])

    # --- negative: role without permission cannot register the (different) target ---
    candidate_ip_denied = str(ipaddress.ip_network(subnet["CidrBlock"]).network_address + 11)
    deny_creds = sts.assume_role(RoleArn=deny_role_arn, RoleSessionName="sim2real-deny")["Credentials"]
    deny_elbv2 = _client_with_creds(ctx, "elbv2", deny_creds)
    code, message = _wait_for_error(
        lambda: deny_elbv2.register_targets(
            TargetGroupArn=tg_arn, Targets=[{"Id": candidate_ip_denied, "Port": 80}]
        ),
        timeout_s=60,
    )
    assert code == "AccessDenied", f"expected AccessDenied, got {code!r}"
    account_id = deny_role_arn.split(":")[4]
    action = "elasticloadbalancing:RegisterTargets"
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{deny_role_name}/sim2real-deny is not "
        f"authorized to perform: {action} on resource: {tg_arn} with an explicit deny in an "
        f"identity-based policy"
    )
    assert message == expected_message, f"AccessDenied message {message!r}, expected {expected_message!r}"

    targets_after_denied = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    assert all(t["Target"]["Id"] != candidate_ip_denied for t in targets_after_denied), (
        f"the denied IP {candidate_ip_denied!r} appears registered despite the explicit Deny: {targets_after_denied!r}"
    )


def _ensure_elb_service_linked_role(iam, timeout_s=60, interval_s=5):
    """Registering IP targets can transiently 500 (InternalFailure) if the
    AWSServiceRoleForElasticLoadBalancing service-linked role hasn't been created yet in
    this account; create it explicitly (idempotent — ignore AlreadyExists), then poll for
    it to actually become visible rather than assuming a fixed propagation delay."""
    from botocore.exceptions import ClientError

    try:
        iam.create_service_linked_role(AWSServiceName="elasticloadbalancing.amazonaws.com")
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidInput", "AlreadyExists"):
            raise

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName="AWSServiceRoleForElasticLoadBalancing")
            return
        except ClientError:
            time.sleep(interval_s)
    raise AssertionError("AWSServiceRoleForElasticLoadBalancing never became visible via get_role")


def _wait_for_error(fn, timeout_s=60, interval_s=3):
    """IAM principal propagation into the ELB control plane can lag briefly, during
    which an unauthorized call may surface as a transient InternalFailure rather than
    the eventual AccessDenied. Retry until we observe a stable access-denied code, and
    return its (code, message). A SUCCESS raises: the target accepted a denied call."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            result = fn()
        except ClientError as exc:
            last = (exc.response["Error"]["Code"], exc.response["Error"].get("Message", ""))
            if last[0] in ("AccessDenied", "AccessDeniedException"):
                return last
            time.sleep(interval_s)
            continue
        raise AssertionError(f"expected AccessDenied, but the call SUCCEEDED and returned {result!r}")
    raise AssertionError(f"no access-denied error within {timeout_s}s; last error {last!r}")


def _wait_for_success(fn, timeout_s=60, interval_s=3):
    """IAM principal propagation into the ELB control plane can lag briefly after a role is
    created/scoped, during which a call that WILL eventually succeed can transiently surface
    as InternalFailure. Retry until it succeeds (or re-raise the last error at the deadline)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _default_vpc_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to attach the target group to")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    return vpc_id, [s["SubnetId"] for s in subnets]


def _register_task_def(ctx, container_name="web", container_port=80):
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-taskdef-")
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": container_name,
                "image": "public.ecr.aws/docker/library/httpd:2.4",
                "portMappings": [{"containerPort": container_port, "protocol": "tcp"}],
                "essential": True,
            }
        ],
        tags=[{"key": "sim2real:managed", "value": "true"}],
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=arn))
    return arn


def _wait_role_assumable(sts, role_arn, timeout_s=60, interval_s=3):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-probe")["Credentials"]
            del creds
            return
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"role {role_arn} never became assumable: {last_exc}")


def _client_with_creds(ctx, service, creds):
    return ctx.client(service, creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })



def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
