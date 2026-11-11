"""task-describe-missing-reason."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "task-describe-missing-reason"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeTasks reports an unknown task ID in failures[] with reason MISSING, not as an
    exception, in the same call that returns a real running task in tasks[]."""
    ecs = ctx.client("ecs")
    cluster = _create_cluster(ctx, ecs)
    net = _default_network(ctx)
    task_def_arn = _register_sleeper_task_def(ctx, ecs)
    real_task_arn = _run_task(ctx, ecs, cluster["clusterArn"], task_def_arn, net)

    prefix = cluster["clusterArn"].split(":cluster/")[0]
    bogus = f"{prefix}:task/{cluster['clusterName']}/00000000000000000000000000000000"

    resp = ecs.describe_tasks(cluster=cluster["clusterArn"], tasks=[real_task_arn, bogus])
    found = {t["taskArn"]: t for t in resp["tasks"]}
    failures = {f["arn"]: f for f in resp.get("failures", [])}

    assert real_task_arn in found, f"expected the real task in tasks[], got {resp}"
    assert real_task_arn not in failures, f"real task must not be reported as a failure: {resp}"
    assert bogus not in found, f"bogus task must not be reported in tasks[]: {resp}"
    assert bogus in failures, f"expected the bogus task in failures[], got {resp}"
    assert failures[bogus].get("reason") == "MISSING", failures[bogus]



# Codes that mean "the control plane is busy", never "your request was wrong".
_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "RequestLimitExceeded",
    "TooManyRequestsException",
)


def _retry_throttled(fn, attempts: int = 7, base_delay: float = 2.0):
    """ECS control-plane mutations have a low sustained rate limit; throttling is never
    the behaviour under test, so absorb it with bounded backoff."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(min(base_delay * (2**i), 20.0))
    raise last


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise


def _create_cluster(ctx, ecs, name=None, **kwargs) -> dict:
    name = name or ctx.unique_name("sim2real-behav-ecs-cluster-")
    resp = _retry_throttled(
        lambda: ecs.create_cluster(
            clusterName=name, tags=[{"key": "sim2real", "value": "true"}], **kwargs
        )
    )
    arn = resp["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ecs.delete_cluster(cluster=arn)))
    return resp["cluster"]


def _default_network(ctx) -> dict:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    if not subnets:
        raise AssertionError("no subnets available in VPC to place a Fargate task")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    ).get("SecurityGroups", [])
    return {
        "subnets": [subnets[0]["SubnetId"]],
        "security_groups": [sgs[0]["GroupId"]] if sgs else [],
    }


def _register_sleeper_task_def(ctx, ecs) -> str:
    family = ctx.unique_name("sim2real-behav-ecs-td-")
    resp = _retry_throttled(
        lambda: ecs.register_task_definition(
            family=family,
            requiresCompatibilities=["FARGATE"],
            networkMode="awsvpc",
            cpu="256",
            memory="512",
            containerDefinitions=[
                {
                    "name": "sleeper",
                    "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                    "command": ["sleep", "600"],
                    "essential": True,
                }
            ],
            tags=[{"key": "sim2real", "value": "true"}],
        )
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


def _run_task(ctx, ecs, cluster_arn: str, task_def_arn: str, net: dict) -> str:
    resp = _retry_throttled(
        lambda: ecs.run_task(
            cluster=cluster_arn,
            taskDefinition=task_def_arn,
            launchType="FARGATE",
            count=1,
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": net["subnets"],
                    "securityGroups": net["security_groups"],
                    "assignPublicIp": "ENABLED",
                }
            },
            tags=[{"key": "sim2real", "value": "true"}],
        )
    )
    assert not resp.get("failures"), f"unexpected RunTask failures: {resp.get('failures')}"
    task_arn = resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="sim2real-behavioral-cleanup")
        )
    )
    return task_arn


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister a task definition revision, then delete it: a deregistered revision stays
    INACTIVE until DeleteTaskDefinitions removes it. An already-deleted revision is fine; any
    other failure raises."""
    from botocore.exceptions import ClientError

    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    arn = described["taskDefinitionArn"]
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
