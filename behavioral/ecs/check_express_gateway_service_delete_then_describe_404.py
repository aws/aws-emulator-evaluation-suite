"""express-gateway-service-delete-then-describe-404."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "express-gateway-service-delete-then-describe-404"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteExpressGatewayService, DescribeExpressGatewayService never reports stale ACTIVE."""
    from botocore.exceptions import ClientError

    roles = _setup_express_gateway_roles(ctx)
    ecs = ctx.client("ecs")
    service_name = ctx.unique_name("sim2real-expgw-")
    ctx.on_cleanup(lambda: _retire_task_definitions(ecs, f"default-{service_name}"))

    create_resp = _create_express_gateway_with_retry(ecs, service_name, roles)
    service_arn = create_resp["service"]["serviceArn"]
    ctx.on_cleanup(lambda: _delete_express_gateway_best_effort(ecs, service_arn))

    # positive control: while alive, it reports ACTIVE
    active_status = _poll_until(
        lambda: ecs.describe_express_gateway_service(serviceArn=service_arn)["service"]["status"]["statusCode"],
        lambda s: s in ("ACTIVE", "INACTIVE"),
        timeout_s=600.0,
        interval_s=2.0,
    )
    assert active_status == "ACTIVE", f"expected ACTIVE before delete, got {active_status}"

    ecs.delete_express_gateway_service(serviceArn=service_arn)

    # immediately after delete, describe must not report stale ACTIVE
    try:
        immediate = ecs.describe_express_gateway_service(serviceArn=service_arn)["service"]["status"]["statusCode"]
        assert immediate != "ACTIVE", f"describe reported stale ACTIVE right after delete: {immediate}"
    except ClientError as err:
        error = (err.response["Error"]["Code"], err.response["Error"].get("Message"))
        expected = ("ResourceNotFoundException", "Service not found")
        assert error == expected, f"expected {expected!r} immediately after delete, got {error!r}"

    # eventually the service settles into a terminal, non-ACTIVE outcome
    def _terminal_probe():
        try:
            return ("status", ecs.describe_express_gateway_service(serviceArn=service_arn)["service"]["status"]["statusCode"])
        except ClientError as err:
            return ("error", (err.response["Error"]["Code"], err.response["Error"].get("Message")))

    gone = ("error", ("ResourceNotFoundException", "Service not found"))
    kind, value = _poll_until(
        _terminal_probe,
        lambda kv: kv == gone or kv == ("status", "INACTIVE"),
        timeout_s=300.0,
        interval_s=2.0,
    )
    assert (kind, value) in (gone, ("status", "INACTIVE")), (
        f"expected a terminal not-found or INACTIVE outcome, got {kind}={value}"
    )

    # a mutation on the dead id must also fail (not just describe) - it can never
    # succeed again regardless of which terminal shape (gone vs INACTIVE) was reached
    try:
        ecs.update_express_gateway_service(serviceArn=service_arn, healthCheckPath="/after-delete")
        raise AssertionError("UpdateExpressGatewayService unexpectedly succeeded against a deleted service")
    except ClientError as err:
        mutate = (err.response["Error"]["Code"], err.response["Error"].get("Message"))
    expected = ("InvalidParameterException", f"Resource not found: {service_arn}")
    assert mutate == expected, (
        f"expected UpdateExpressGatewayService on a deleted service to fail with {expected!r}, "
        f"got {mutate!r} (terminal state was {kind}={value})"
    )


# ===== helpers =====

def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _setup_express_gateway_roles(ctx):
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    exec_role_name = ctx.unique_name("sim2real-ecs-exec-")
    infra_role_name = ctx.unique_name("sim2real-ecs-expinfra-")

    exec_trust = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    )
    infra_trust = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    )
    exec_policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    infra_policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSInfrastructureRoleforExpressGatewayServices"

    role_tags = [{"Key": "sim2real", "Value": "true"}]
    try:
        exec_arn = iam.create_role(
            RoleName=exec_role_name, AssumeRolePolicyDocument=exec_trust, Tags=role_tags
        )["Role"]["Arn"]
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=exec_role_name))
        iam.attach_role_policy(RoleName=exec_role_name, PolicyArn=exec_policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=exec_role_name, PolicyArn=exec_policy_arn))

        infra_arn = iam.create_role(
            RoleName=infra_role_name, AssumeRolePolicyDocument=infra_trust, Tags=role_tags
        )["Role"]["Arn"]
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=infra_role_name))
        iam.attach_role_policy(RoleName=infra_role_name, PolicyArn=infra_policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=infra_role_name, PolicyArn=infra_policy_arn))
    except ClientError as err:
        raise AssertionError(f"unreachable: cannot provision IAM roles for Express Gateway service ({err.response['Error']['Code']})")

    return {"execution_role_arn": exec_arn, "infrastructure_role_arn": infra_arn}


def _create_express_gateway_with_retry(ecs, service_name, roles, timeout_s=120.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return ecs.create_express_gateway_service(
                serviceName=service_name,
                executionRoleArn=roles["execution_role_arn"],
                infrastructureRoleArn=roles["infrastructure_role_arn"],
                primaryContainer={"image": "public.ecr.aws/nginx/nginx:1.27", "containerPort": 80},
                tags=[{"key": "sim2real", "value": "true"}],
            )
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = str(err)
            last_err = err
            if code in ("ClientException", "InvalidParameterException", "AccessDeniedException") and "ssume" in msg.lower():
                time.sleep(2)
                continue
            raise AssertionError(f"unreachable: CreateExpressGatewayService rejected in this account/region ({code})")
    raise AssertionError(f"unreachable: CreateExpressGatewayService never succeeded after role propagation retries: {last_err}")


def _delete_express_gateway_best_effort(ecs, service_arn):
    from botocore.exceptions import ClientError

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
