"""express-gateway-service-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "express-gateway-service-lifecycle"
GROUP = "state-machine"
SERVICES = ["ecs"]

_SKIP_CODES = {
    "UnsupportedFeatureException",
    "AccessDeniedException",
}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateExpressGatewayService->DescribeExpressGatewayService->UpdateExpressGatewayService->
    DeleteExpressGatewayService transitions correctly, ending in a 404 after delete."""
    ecs = ctx.client("ecs")
    if not hasattr(ecs, "create_express_gateway_service"):
        raise AssertionError("this botocore build has no ExpressGatewayService API")

    iam = ctx.client("iam")

    cluster_name = ctx.unique_name("sim2real-behav-xgw-cluster-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    role_name = ctx.unique_name("sim2real-behav-xgw-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ecs.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: iam.delete_role(RoleName=role_name)))

    exec_role_name = ctx.unique_name("sim2real-behav-xgw-exec-")
    exec_trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    exec_role_arn = iam.create_role(
        RoleName=exec_role_name, AssumeRolePolicyDocument=json.dumps(exec_trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: iam.delete_role(RoleName=exec_role_name)))
    exec_policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=exec_role_name, PolicyArn=exec_policy_arn)
    ctx.on_cleanup(
        lambda: _ignore_client_error(
            lambda: iam.detach_role_policy(RoleName=exec_role_name, PolicyArn=exec_policy_arn)
        )
    )

    # Confirmed against real AWS: the managed policy lives under the
    # "service-role/" path, not the bare "/" path - attaching the bare-path ARN
    # 404s with NoSuchEntity, while this one attaches cleanly.
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSInfrastructureRoleforExpressGatewayServices"
    try:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchEntity":
            raise AssertionError(
                f"managed policy {policy_arn} does not exist in this account/partition - "
                "express gateway service feature unavailable"
            )
        raise
    ctx.on_cleanup(
        lambda: _ignore_client_error(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        )
    )

    service_name = ctx.unique_name("sim2real-behav-xgw-svc-")
    ctx.on_cleanup(lambda: _retire_task_definitions(ecs, f"{cluster_name}-{service_name}"))

    created = None
    last_code = None
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            created = ecs.create_express_gateway_service(
                cluster=cluster_arn,
                serviceName=service_name,
                infrastructureRoleArn=role_arn,
                executionRoleArn=exec_role_arn,
                primaryContainer={
                    "image": "public.ecr.aws/docker/library/httpd:2.4",
                    "containerPort": 80,
                },
                healthCheckPath="/",
            )
            break
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            message = str(exc).lower()
            role_propagating = "role" in message or "not found" in message or "assume" in message
            if last_code in ("ClientException", "AccessDeniedException") and role_propagating:
                time.sleep(5)  # IAM role/policy attachment propagation
                continue
            if last_code in _SKIP_CODES:
                raise AssertionError(f"express gateway service unavailable: {last_code}: {exc}")
            raise
    if created is None:
        raise AssertionError(f"could not create express gateway service after retries: {last_code}")

    service_arn = created["service"]["serviceArn"]
    ctx.on_cleanup(
        lambda: _ignore_client_error(lambda: ecs.delete_express_gateway_service(serviceArn=service_arn))
    )
    assert created["service"]["serviceName"] == service_name, (
        f"expected serviceName {service_name!r}, got {created['service']['serviceName']!r}"
    )

    described = _poll_until(
        lambda: ecs.describe_express_gateway_service(serviceArn=service_arn),
        lambda d: d["service"]["status"]["statusCode"] == "ACTIVE",
        timeout_s=300,
        interval_s=10,
    )
    assert described["service"]["cluster"] == cluster_arn, (
        f"expected cluster {cluster_arn!r}, got {described['service']['cluster']!r}"
    )

    ecs.update_express_gateway_service(serviceArn=service_arn, healthCheckPath="/index.html")
    updated = _poll_until(
        lambda: ecs.describe_express_gateway_service(serviceArn=service_arn),
        lambda d: d["service"]["status"]["statusCode"] == "ACTIVE",
        timeout_s=120,
        interval_s=5,
    )
    assert updated["service"]["serviceArn"] == service_arn, (
        f"expected serviceArn {service_arn!r}, got {updated['service']['serviceArn']!r}"
    )

    ecs.delete_express_gateway_service(serviceArn=service_arn)

    def _post_delete_probe():
        try:
            return ("status", ecs.describe_express_gateway_service(serviceArn=service_arn)["service"]["status"]["statusCode"])
        except ClientError as exc:
            return ("error", (exc.response["Error"]["Code"], exc.response["Error"].get("Message")))

    # Real AWS never 404s a deleted Express service within any reasonable poll window: it settles
    # into a still-describable terminal INACTIVE (measured: a 300s poll for ResourceNotFoundException
    # alone never fired). ResourceNotFoundException is accepted too in case a given
    # account/partition GCs it faster, but INACTIVE is the terminal state to expect.
    gone = ("error", ("ResourceNotFoundException", "Service not found"))
    kind, value = _poll_until(
        _post_delete_probe,
        lambda kv: kv == gone or kv == ("status", "INACTIVE"),
        timeout_s=300,
        interval_s=10,
    )
    assert (kind, value) in (gone, ("status", "INACTIVE")), (
        f"expected a terminal not-found-or-INACTIVE state after delete, got {(kind, value)!r}"
    )

    # Whichever terminal shape it took, the service is unusable: a mutation against it must fail.
    mutate = _error(
        lambda: ecs.update_express_gateway_service(serviceArn=service_arn, healthCheckPath="/")
    )
    expected = ("InvalidParameterException", f"Resource not found: {service_arn}")
    assert mutate == expected, f"expected update on the deleted service to fail with {expected!r}, got {mutate!r}"


# ===== helpers =====
def _error(fn):
    """Call fn(); return its botocore (code, message). A call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _ignore_client_error(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("ClusterNotFoundException", "NoSuchEntity", "ServiceNotFoundException")
            and not (err["Code"] == "InvalidParameterException" and "Resource not found" in err.get("Message", ""))
        ):
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


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
