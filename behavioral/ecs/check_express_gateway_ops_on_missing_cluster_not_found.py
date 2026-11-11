"""express-gateway-ops-on-missing-cluster-not-found."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "express-gateway-ops-on-missing-cluster-not-found"
GROUP = 'overly-permissive'
SERVICES = ['ecs']

_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
_ECS_TAGS = [{"key": "sim2real:check", "value": CHECK}]
_IAM_TAGS = [{"Key": "sim2real:check", "Value": CHECK}]


def _error(fn):
    """Call fn(); return its botocore (code, message). A call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_role(ctx, iam, prefix, trust_service, managed_policy_arns=()):
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    role_name = ctx.unique_name(prefix)[:64]
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_IAM_TAGS
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    for arn in managed_policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
        ctx.on_cleanup(lambda a=arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=a))
    return role_arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Create/Delete/Describe/UpdateExpressGatewayService on a nonexistent cluster return
    ClusterNotFoundException; on a real cluster, Delete/Describe/Update of an unknown service answer
    the service-not-found family instead, so the rejection is keyed on cluster existence."""
    ecs = ctx.client("ecs")
    if not hasattr(ecs, "create_express_gateway_service"):
        raise AssertionError("client lacks Express Gateway Service operations")

    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_cluster = ctx.unique_name("sim2real-no-such-cluster-")
    infra_role_arn = _create_role(ctx, iam, "sim2real-xgw-infra-role-", "ecs.amazonaws.com")
    exec_role_arn = _create_role(
        ctx, iam, "sim2real-xgw-exec-role-", "ecs-tasks.amazonaws.com", managed_policy_arns=[_EXEC_POLICY]
    )
    fake_service_arn = (
        f"arn:aws:ecs:{ctx.region}:{account_id}:service/{bogus_cluster}/{ctx.unique_name('sim2real-xgw-')}"
    )

    real_cluster_name = ctx.unique_name("sim2real-real-cluster-")
    real_cluster_arn = ecs.create_cluster(clusterName=real_cluster_name, tags=_ECS_TAGS)["cluster"][
        "clusterArn"
    ]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=real_cluster_arn))
    real_cluster_service_arn = (
        f"arn:aws:ecs:{ctx.region}:{account_id}:service/{real_cluster_name}/{ctx.unique_name('sim2real-xgw-')}"
    )

    cluster_missing = ("ClusterNotFoundException", "Cluster not found.")

    # Create has no real-cluster control here: a successful create provisions an ALB-backed
    # Fargate service asynchronously, which can outlive the cleanup budget.

    error = _error(
        lambda: ecs.create_express_gateway_service(
            cluster=bogus_cluster,
            infrastructureRoleArn=infra_role_arn,
            executionRoleArn=exec_role_arn,
            primaryContainer={"image": "public.ecr.aws/amazonlinux/amazonlinux:2023"},
        )
    )
    assert error == cluster_missing, f"CreateExpressGatewayService: got {error!r}"

    error = _error(lambda: ecs.delete_express_gateway_service(serviceArn=fake_service_arn))
    assert error == cluster_missing, f"DeleteExpressGatewayService: got {error!r}"
    control = _error(
        lambda: ecs.delete_express_gateway_service(serviceArn=real_cluster_service_arn)
    )
    assert control == ("ServiceNotFoundException", "Service not found"), (
        "positive control: DeleteExpressGatewayService against a REAL cluster with an "
        f"unknown service must answer ServiceNotFoundException, got {control!r} - "
        "otherwise the assertion above cannot tell 'this cluster is missing' from "
        "'every call is rejected'"
    )

    error = _error(lambda: ecs.describe_express_gateway_service(serviceArn=fake_service_arn))
    assert error == cluster_missing, f"DescribeExpressGatewayService: got {error!r}"
    control = _error(
        lambda: ecs.describe_express_gateway_service(serviceArn=real_cluster_service_arn)
    )
    assert control == ("ResourceNotFoundException", "Service not found"), (
        "positive control: DescribeExpressGatewayService against a REAL cluster with an "
        f"unknown service must answer ResourceNotFoundException, got {control!r}"
    )

    error = _error(
        lambda: ecs.update_express_gateway_service(serviceArn=fake_service_arn, cpu="512")
    )
    assert error == cluster_missing, f"UpdateExpressGatewayService: got {error!r}"
    control = _error(
        lambda: ecs.update_express_gateway_service(serviceArn=real_cluster_service_arn, cpu="512")
    )
    # On a real cluster, Update answers an unknown service with InvalidParameterException
    # naming the service ARN, not ServiceNotFoundException.
    expected = ("InvalidParameterException", f"Resource not found: {real_cluster_service_arn}")
    assert control == expected, (
        "positive control: UpdateExpressGatewayService against a REAL cluster with an "
        f"unknown service: expected {expected!r}, got {control!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
