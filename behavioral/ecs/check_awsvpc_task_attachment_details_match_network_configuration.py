"""awsvpc-task-attachment-details-match-network-configuration."""
from __future__ import annotations

import ipaddress
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "awsvpc-task-attachment-details-match-network-configuration"
GROUP = 'task-networking'
SERVICES = ['ecs']

_CONTAINERS = [
    {
        "name": "app",
        "image": "public.ecr.aws/docker/library/busybox:1.36",
        "essential": True,
        "command": ["sh", "-c", "sleep 600"],
    }
]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")
        time.sleep(interval_s)


def _eni_attachment(task):
    """The task's single ElasticNetworkInterface attachment, or None."""
    if not task:
        return None
    enis = [a for a in task.get("attachments", []) if a.get("type") == "ElasticNetworkInterface"]
    assert len(enis) <= 1, f"an awsvpc task carries {len(enis)} ENI attachments: {enis!r}"
    return enis[0] if enis else None


def _details(attachment) -> dict:
    return {d["name"]: d.get("value") for d in attachment.get("details", [])}


def _stop_and_wait(ecs, cluster: str, task_arn: str, timeout_s: float = 300.0) -> None:
    """Stop the task and wait until it is STOPPED, so its ENI leaves the subnet."""
    ecs.stop_task(cluster=cluster, task=task_arn, reason="sim2real cleanup")
    deadline = time.monotonic() + timeout_s
    while True:
        rows = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"]
        if not rows or rows[0].get("lastStatus") == "STOPPED":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"task still {rows[0].get('lastStatus')!r} after {timeout_s}s")
        time.sleep(5.0)


def _delete_task_definition(ecs, arn: str) -> None:
    ecs.deregister_task_definition(taskDefinition=arn)
    ecs.delete_task_definitions(taskDefinitions=[arn])


@tags("axis:happy-path", "cap:c3", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An awsvpc Fargate task's ENI attachment reaches ATTACHED with ``subnetId`` equal to the
    requested subnet, an ``eni-`` interface id and a ``privateIPv4Address`` inside that subnet's
    CIDR, and RunTask and DescribeTasks name the same attachment.
    """
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    net = ctx.network()
    subnet_id = net.subnet_ids[0]
    subnets = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"]
    assert [s["SubnetId"] for s in subnets] == [subnet_id], f"DescribeSubnets returned {subnets!r}"
    subnet_cidr = ipaddress.ip_network(subnets[0]["CidrBlock"])

    cluster = ctx.unique_name("sim2real-behav-ecs-eni-")
    ecs.create_cluster(clusterName=cluster, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(_teardown(lambda: ecs.delete_cluster(cluster=cluster), "ClusterNotFoundException"))

    td_arn = ecs.register_task_definition(
        family=cluster,
        containerDefinitions=_CONTAINERS,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        tags=[{"key": "sim2real", "value": CHECK}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _delete_task_definition(ecs, td_arn))

    resp = ecs.run_task(
        cluster=cluster,
        taskDefinition=td_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration={"awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [net.security_group_id],
            "assignPublicIp": "ENABLED",
        }},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    assert not resp.get("failures"), f"RunTask failures: {resp.get('failures')!r}"
    assert len(resp.get("tasks", [])) == 1, f"RunTask started {len(resp.get('tasks', []))} tasks"
    task_arn = resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(_teardown(lambda: _stop_and_wait(ecs, cluster, task_arn), "InvalidParameterException"))

    started = _eni_attachment(resp["tasks"][0])
    assert started is not None, f"RunTask returned no ENI attachment: {resp['tasks'][0].get('attachments')!r}"
    assert _details(started).get("subnetId") == subnet_id, (
        f"RunTask attachment subnetId is {_details(started).get('subnetId')!r}, "
        f"expected the requested subnet"
    )

    def _attachment():
        rows = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"]
        return _eni_attachment(rows[0]) if rows else None

    attached = _poll_until(
        _attachment,
        lambda a: a is not None and (a.get("status") == "ATTACHED" or a.get("status") in ("DELETED", "FAILED")),
        timeout_s=240.0,
    )
    assert attached["status"] == "ATTACHED", f"ENI attachment ended {attached['status']!r}: {attached!r}"
    assert attached["id"] == started["id"], (
        "DescribeTasks names a different attachment id than RunTask returned"
    )
    details = _details(attached)
    assert details.get("subnetId") == subnet_id, (
        f"attached ENI subnetId is {details.get('subnetId')!r}, expected the requested subnet"
    )
    eni_id = details.get("networkInterfaceId") or ""
    assert eni_id.startswith("eni-") and len(eni_id) > len("eni-"), (
        f"networkInterfaceId has the wrong shape: {eni_id!r}"
    )
    ip = details.get("privateIPv4Address")
    assert ip, f"attachment details carry no privateIPv4Address: {sorted(details)!r}"
    assert ipaddress.ip_address(ip) in subnet_cidr, (
        f"privateIPv4Address {ip!r} is outside the requested subnet's CIDR {str(subnet_cidr)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
