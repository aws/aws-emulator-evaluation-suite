"""concurrent-update-job-queue-optimistic-lock."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-update-job-queue-optimistic-lock"
GROUP = "concurrency"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateJobQueue calls on the same queue serialize server-side: the
    queue converges to exactly one of the two submitted priorities, never a corrupted or
    intermediate value, and DescribeJobQueues reflects a single consistent VALID state."""
    batch = ctx.client("batch")
    subnet_id, sg_id = _create_network(ctx)

    ce_name = ctx.unique_name("sim2real-batch-ce-")
    queue_name = ctx.unique_name("sim2real-batch-jq-")
    # Single combined teardown, registered before either create so a failed queue create cannot
    # leak the compute environment. The CE and JQ each disabling+settling sequentially can exceed
    # the engine's 60s cleanup budget; disabling both concurrently keeps it well inside.
    ctx.on_cleanup(lambda: _teardown(ctx, ce_name, queue_name))
    ce_arn = _create_fargate_ce(ctx, ce_name, 2, [subnet_id], sg_id)
    _create_job_queue(ctx, queue_name, [{"order": 1, "computeEnvironment": ce_arn}], priority=1)

    outcomes: dict[str, Any] = {}

    def _update(priority: int, key: str) -> None:
        try:
            batch.update_job_queue(jobQueue=queue_name, priority=priority)
            outcomes[key] = "ok"
        except ClientError as e:
            outcomes[key] = e.response["Error"]["Code"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(_update, 5, "a"),
            pool.submit(_update, 9, "b"),
        ]
        for f in futures:
            f.result()

    # At least one of the two racing updates must have been actually applied.
    assert "ok" in outcomes.values(), f"neither concurrent UpdateJobQueue call succeeded: {outcomes}"

    final = _poll_stable(
        lambda: batch.describe_job_queues(jobQueues=[queue_name])["jobQueues"][0],
        settled=lambda jq: jq["status"] == "VALID",
        key=lambda jq: jq["priority"],
        timeout_s=120,
        interval_s=4,
        required_consecutive=3,
    )
    assert final["priority"] in (5, 9), f"priority converged to an unexpected value: {final['priority']}"
    assert final["jobQueueName"] == queue_name, (
        f"expected describe_job_queues to name the queue {queue_name!r}, got {final['jobQueueName']!r}"
    )
    assert final["status"] == "VALID", f"expected job queue status VALID after convergence, got {final['status']!r}"



def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _poll_stable(probe, settled, key, timeout_s=120.0, interval_s=4.0, required_consecutive=3):
    """Poll until `settled(value)` holds AND `key(value)` has been identical on
    `required_consecutive` consecutive settled samples — proving convergence rather than
    trusting a single snapshot that happened to land on a VALID read mid-reconciliation."""
    deadline = time.monotonic() + timeout_s
    last_key = None
    last_value = None
    streak = 0
    while time.monotonic() < deadline:
        value = probe()
        if settled(value):
            current_key = key(value)
            if current_key == last_key:
                streak += 1
                if streak >= required_consecutive:
                    return value
            else:
                streak = 1
                last_key = current_key
            last_value = value
        else:
            streak = 0
            last_key = None
        time.sleep(interval_s)
    raise AssertionError(
        f"value never stabilized within {timeout_s}s (required {required_consecutive} consecutive "
        f"settled matches); last={last_value}"
    )


def _create_network(ctx) -> tuple[str, str]:
    """(subnet_id, security_group_id) in an internet-routable VPC this check creates and tears down.

    The check owns its networking: a VPC, one public subnet, an internet gateway with a default
    route (so a Fargate task can pull a public image), and the VPC's own default security group.
    """
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.182.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-batch-vpc-")}])
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.182.1.0/24", AvailabilityZone=az)["Subnet"][
        "SubnetId"
    ]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    igw_id = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id)))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(
        lambda: _delete_with_retry(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id))
    )
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"][0][
        "RouteTableId"
    ]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    sg_id = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return subnet_id, sg_id


def _delete_with_retry(fn, timeout_s: float = 600.0) -> None:
    """Retry a network delete while Fargate/Batch ENIs drain (DependencyViolation)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code.endswith(".NotFound") or code in ("Gateway.NotAttached",):
                return
            if code != "DependencyViolation" or time.monotonic() > deadline:
                raise
            time.sleep(15)


def _create_fargate_ce(ctx, name: str, max_vcpus: int, subnets: list, sg_id: str) -> str:
    batch = ctx.client("batch")
    batch.create_compute_environment(
        computeEnvironmentName=name,
        type="MANAGED",
        state="ENABLED",
        computeResources={
            "type": "FARGATE",
            "maxvCpus": max_vcpus,
            "subnets": subnets,
            "securityGroupIds": [sg_id],
        },
        tags=_MANAGED_TAGS,
    )
    ce = _poll_until(
        lambda: batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"][0],
        lambda ce: ce["status"] in ("VALID", "INVALID"),
        timeout_s=120,
        interval_s=5,
    )
    assert ce["status"] == "VALID", f"compute environment failed to validate: {ce.get('statusReason')}"
    return ce["computeEnvironmentArn"]


def _create_job_queue(ctx, name: str, ce_order: list, priority: int) -> str:
    batch = ctx.client("batch")
    resp = batch.create_job_queue(
        jobQueueName=name,
        state="ENABLED",
        priority=priority,
        computeEnvironmentOrder=ce_order,
        tags=_MANAGED_TAGS,
    )
    jq = _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"][0],
        lambda jq: jq["status"] in ("VALID", "INVALID"),
        timeout_s=120,
        interval_s=4,
    )
    assert jq["status"] == "VALID", f"job queue failed to validate: {jq.get('statusReason')}"
    return resp["jobQueueArn"]


def _teardown(ctx, ce_name: str, jq_name: str) -> None:
    """Disable the CE and the JQ concurrently (rather than one full drain-then-delete cycle
    after another) so both settle together. The JQ must be deleted before the CE it
    references, and the CE delete waits out the JQ's asynchronous delete.
    """
    batch = ctx.client("batch")

    def _disable_ce() -> None:
        try:
            batch.update_compute_environment(computeEnvironment=ce_name, state="DISABLED")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise

    def _disable_jq() -> None:
        try:
            batch.update_job_queue(jobQueue=jq_name, state="DISABLED")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise

    with ThreadPoolExecutor(max_workers=2) as pool:
        for f in [pool.submit(_disable_ce), pool.submit(_disable_jq)]:
            f.result()

    def _both_settled() -> bool:
        ces = batch.describe_compute_environments(computeEnvironments=[ce_name])["computeEnvironments"]
        jqs = batch.describe_job_queues(jobQueues=[jq_name])["jobQueues"]
        ce_status = ces[0]["status"] if ces else "VALID"
        jq_status = jqs[0]["status"] if jqs else "VALID"
        return ce_status == "VALID" and jq_status == "VALID"

    try:
        _poll_until(_both_settled, lambda ok: ok, timeout_s=40, interval_s=3)
    except AssertionError:
        pass

    batch.delete_job_queue(jobQueue=jq_name)

    # The queue deletes asynchronously, and the compute environment refuses its delete while the
    # queue still references it: retry that answer every 2 s for up to 300 s, then raise.
    deadline = time.monotonic() + 300
    while True:
        try:
            batch.delete_compute_environment(computeEnvironment=ce_name)
            return
        except ClientError as exc:
            if "JobQueue relationship" not in exc.response["Error"].get("Message", ""):
                raise
            if time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
