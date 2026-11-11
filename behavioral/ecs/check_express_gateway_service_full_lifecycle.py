"""express-gateway-service-full-lifecycle."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "express-gateway-service-full-lifecycle"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An Express Gateway service reaches ACTIVE, an UpdateExpressGatewayService health check
    path change shows on describe, and after DeleteExpressGatewayService it is gone."""

    ecs = ctx.client("ecs")
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    ctx.client("sts")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("unreachable: no shared network VPC available for Express Gateway Service")
    vpc_id = vpcs[0]["VpcId"]
    subnets = [s["SubnetId"] for s in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]][:2]
    if len(subnets) < 2:
        raise AssertionError("unreachable: shared network needs at least 2 subnets for an ALB")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("unreachable: shared network has no default security group")
    sg_id = sgs[0]["GroupId"]

    suffix = uuid.uuid4().hex[:10]
    infra_role_name = f"sim2real-ecs-egw-infra-{suffix}"
    exec_role_name = f"sim2real-ecs-egw-exec-{suffix}"

    infra_trust = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    )
    exec_trust = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    )

    try:
        infra_role_arn = iam.create_role(
            RoleName=infra_role_name,
            AssumeRolePolicyDocument=infra_trust,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["Role"]["Arn"]
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=infra_role_name))
        infra_policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSInfrastructureRoleforExpressGatewayServices"
        iam.attach_role_policy(RoleName=infra_role_name, PolicyArn=infra_policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=infra_role_name, PolicyArn=infra_policy_arn))

        exec_role_arn = iam.create_role(
            RoleName=exec_role_name,
            AssumeRolePolicyDocument=exec_trust,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["Role"]["Arn"]
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=exec_role_name))
        exec_policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
        iam.attach_role_policy(RoleName=exec_role_name, PolicyArn=exec_policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=exec_role_name, PolicyArn=exec_policy_arn))
    except ClientError as e:
        raise AssertionError(f"unreachable: cannot provision IAM roles for Express Gateway Service: {e}")

    cluster_arn = ecs.create_cluster(
        clusterName=ctx.unique_name("sim2real-ecs-"),
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    service_name = ctx.unique_name("sim2real-egw-")
    family = f"{cluster_arn.rsplit('/', 1)[-1]}-{service_name}"
    ctx.on_cleanup(lambda: _retire_task_definitions(ecs, family))
    last_exc = None
    created = None
    # IAM role propagation: retry the create on its propagation errors for up to 60 s.
    left = ctx.time_left()
    create_deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    while time.monotonic() < create_deadline:
        try:
            created = ecs.create_express_gateway_service(
                cluster=cluster_arn,
                serviceName=service_name,
                infrastructureRoleArn=infra_role_arn,
                executionRoleArn=exec_role_arn,
                healthCheckPath="/",
                cpu="256",
                memory="512",
                primaryContainer={"image": "public.ecr.aws/docker/library/httpd:2.4", "containerPort": 80},
                networkConfiguration={"subnets": subnets, "securityGroups": [sg_id]},
                scalingTarget={"minTaskCount": 1, "maxTaskCount": 1},
                tags=[{"key": "sim2real-check", "value": CHECK}],
            )["service"]
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            last_exc = e
            if code == "UnsupportedFeatureException":
                raise AssertionError(f"unreachable: CreateExpressGatewayService unsupported here: {e}")
            if code in ("InvalidParameterException", "AccessDeniedException", "ClientException"):
                time.sleep(2)
                continue
            raise
    if created is None:
        raise AssertionError(f"unreachable: could not create Express Gateway Service: {last_exc}")

    service_arn = created["serviceArn"]
    ctx.on_cleanup(lambda: _safe_delete_egw(ecs, service_arn))

    active = _poll_until(
        lambda: ecs.describe_express_gateway_service(serviceArn=service_arn)["service"],
        lambda s: s["status"]["statusCode"] in ("ACTIVE", "FAILED"),
        timeout_s=420,
        interval_s=2,
    )
    assert active["status"]["statusCode"] == "ACTIVE", active["status"]
    assert active["serviceName"] == service_name, f"expected serviceName={service_name!r}, got {active['serviceName']!r}"
    assert active["cluster"] == cluster_arn, f"expected cluster={cluster_arn!r}, got {active['cluster']!r}"

    # UpdateExpressGatewayService mutates configuration (health check path); describe's
    # activeConfigurations must reflect the new value at the destination, not just echo the ARN.
    new_health_check_path = "/updated-health"
    ecs.update_express_gateway_service(serviceArn=service_arn, healthCheckPath=new_health_check_path)
    updated = _poll_until(
        lambda: ecs.describe_express_gateway_service(serviceArn=service_arn)["service"],
        lambda s: s["status"]["statusCode"] == "ACTIVE"
        and any(cfg.get("healthCheckPath") == new_health_check_path for cfg in s.get("activeConfigurations", [])),
        timeout_s=300,
        interval_s=2,
    )
    assert updated["serviceArn"] == service_arn, f"expected serviceArn={service_arn!r}, got {updated['serviceArn']!r}"
    assert any(cfg.get("healthCheckPath") == new_health_check_path for cfg in updated["activeConfigurations"]), (
        f"updated healthCheckPath {new_health_check_path!r} not reflected in activeConfigurations: "
        f"{updated['activeConfigurations']}"
    )

    # DeleteExpressGatewayService removes it
    ecs.delete_express_gateway_service(serviceArn=service_arn)

    def _describe_after_delete():
        try:
            svc = ecs.describe_express_gateway_service(serviceArn=service_arn)["service"]
            return svc["status"]["statusCode"]
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message")

    gone = ("ResourceNotFoundException", "Service not found")
    final = _poll_until(
        _describe_after_delete,
        lambda s: s in ("INACTIVE", gone),
        timeout_s=300,
        interval_s=2,
    )
    assert final in ("INACTIVE", gone), final

    # a mutation on the dead service must also fail, not just its own describe
    try:
        ecs.update_express_gateway_service(serviceArn=service_arn, healthCheckPath="/after-delete")
        raise AssertionError("UpdateExpressGatewayService unexpectedly succeeded on a deleted Express Gateway Service")
    except ClientError as e:
        dead_mutation = (e.response["Error"]["Code"], e.response["Error"].get("Message"))
    expected = ("InvalidParameterException", f"Resource not found: {service_arn}")
    assert dead_mutation == expected, f"expected {expected!r}, got {dead_mutation!r}"


def _poll_until(probe, predicate, timeout_s=120, interval_s=3):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _safe_delete_egw(ecs, service_arn):
    try:
        ecs.delete_express_gateway_service(serviceArn=service_arn)
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("ClusterNotFoundException", "ServiceNotFoundException")
            and not (err["Code"] == "InvalidParameterException" and "Resource not found" in err.get("Message", ""))
        ):
            raise


def _retire_task_definitions(ecs, family):
    """Deregister and delete every revision of the task definition family that Express
    Gateway registers for the service; DeleteExpressGatewayService leaves them in place."""
    from botocore.exceptions import ClientError

    arns = []
    for status in ("ACTIVE", "INACTIVE"):
        paginator = ecs.get_paginator("list_task_definitions")
        for page in paginator.paginate(familyPrefix=family, status=status):
            for arn in page["taskDefinitionArns"]:
                if arn.rsplit("/", 1)[-1].rsplit(":", 1)[0] == family:
                    arns.append(arn)
    for arn in arns:
        try:
            ecs.deregister_task_definition(taskDefinition=arn)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted"))
            ):
                raise
    for i in range(0, len(arns), 10):
        ecs.delete_task_definitions(taskDefinitions=arns[i : i + 10])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
