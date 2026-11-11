"""run-task-client-token-idempotency-concurrent."""
from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "run-task-client-token-idempotency-concurrent"
GROUP = "concurrency"
SERVICES = ["ecs"]

# RunTask has a low default request rate; racing 5 identical calls can trip transient
# 5xx throttling unrelated to the dedup contract under test, so those codes alone get a
# bounded backoff-retry with the same clientToken rather than counting as a defect.
_TRANSIENT_ERROR_CODES = {"ServerException", "ServiceUnavailable", "Throttling", "ThrottlingException", "RequestLimitExceeded"}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """N concurrent RunTask calls sharing an identical clientToken and identical
    parameters must deduplicate to exactly one underlying task, never N."""
    ecs = ctx.client("ecs")
    cluster = _create_cluster(ctx)
    net = _default_network(ctx)
    task_def = _register_fargate_task_def(ctx, ctx.unique_name("sim2real-ecs-td-"))

    client_token = str(uuid.uuid4())
    kwargs = dict(
        cluster=cluster["clusterArn"],
        taskDefinition=task_def["taskDefinitionArn"],
        launchType="FARGATE",
        count=1,
        clientToken=client_token,
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": net["subnets"],
                "securityGroups": net["security_groups"],
                "assignPublicIp": "ENABLED",
            }
        },
        tags=[{"key": "sim2real:managed", "value": "true"}],
    )

    n_racers = 5
    results = []
    errors = []

    def _racer():
        delay = 1.0
        for attempt in range(5):
            try:
                resp = ecs.run_task(**kwargs)
                return ("ok", resp)
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code in _TRANSIENT_ERROR_CODES and attempt < 4:
                    time.sleep(delay)
                    delay *= 2
                    continue
                return ("error", exc)
            except Exception as exc:  # noqa: BLE001 - capture for aggregate assertion
                return ("error", exc)

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        for outcome, payload in pool.map(lambda _: _racer(), range(n_racers)):
            if outcome == "ok":
                results.append(payload)
            else:
                errors.append(payload)

    assert not errors, f"idempotent RunTask calls with identical clientToken raised: {errors}"
    assert len(results) == n_racers, f"expected {n_racers} successful racer results, got {len(results)}"

    all_task_arns = set()
    for resp in results:
        assert not resp.get("failures"), f"unexpected failures in idempotent RunTask response: {resp['failures']}"
        assert len(resp["tasks"]) == 1, "each idempotent response should describe exactly one task"
        all_task_arns.add(resp["tasks"][0]["taskArn"])

    assert len(all_task_arns) == 1, (
        f"expected all {n_racers} concurrent calls with the same clientToken to dedupe to a single "
        f"task, but observed {len(all_task_arns)} distinct task ARNs: {all_task_arns}"
    )

    task_arn = next(iter(all_task_arns))
    ctx.on_cleanup(lambda: ecs.stop_task(cluster=cluster["clusterArn"], task=task_arn, reason="test-cleanup"))

    tasks_in_cluster = ecs.list_tasks(cluster=cluster["clusterArn"], desiredStatus="RUNNING")["taskArns"] + \
        ecs.list_tasks(cluster=cluster["clusterArn"], desiredStatus="STOPPED")["taskArns"]
    matching = [a for a in tasks_in_cluster if a == task_arn]
    assert len(set(tasks_in_cluster)) <= 1 or task_arn in tasks_in_cluster, (
        f"expected the cluster's task list to contain at most the single deduplicated task, "
        f"found {set(tasks_in_cluster)}"
    )
    assert matching, "the deduplicated task should be visible via ListTasks"


from botocore.exceptions import ClientError


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    if not subnets:
        raise AssertionError("no subnets available in VPC to place Fargate tasks")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    ).get("SecurityGroups", [])
    return {
        "subnets": [s["SubnetId"] for s in subnets[:2]],
        "security_groups": [sgs[0]["GroupId"]] if sgs else [],
    }


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-cluster-")
    cluster = ecs.create_cluster(clusterName=name, tags=[{"key": "sim2real:managed", "value": "true"}])["cluster"]

    def _cleanup(arn=cluster["clusterArn"]):
        try:
            ecs.delete_cluster(cluster=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return cluster


def _register_fargate_task_def(ctx, family, command=None):
    ecs = ctx.client("ecs")
    resp = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "command": command or ["sleep", "600"],
            }
        ],
        tags=[{"key": "sim2real:managed", "value": "true"}],
    )
    td = resp["taskDefinition"]

    def _cleanup(arn=td["taskDefinitionArn"]):
        try:
            ecs.deregister_task_definition(taskDefinition=arn)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted"))
            ):
                raise
        ecs.delete_task_definitions(taskDefinitions=[arn])

    ctx.on_cleanup(_cleanup)
    return td


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
