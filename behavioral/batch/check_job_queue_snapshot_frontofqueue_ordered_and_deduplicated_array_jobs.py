"""job-queue-snapshot-frontofqueue-ordered-and-deduplicated-array-jobs."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "job-queue-snapshot-frontofqueue-ordered-and-deduplicated-array-jobs"
GROUP = "data-plane"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """With 120 RUNNABLE array-child jobs, GetJobQueueSnapshot's frontOfQueue holds exactly 100
    unique ARNs, all from those children, in ascending earliestTimeAtPosition order: the snapshot
    caps at 100 jobs with no pagination."""
    batch = ctx.client("batch")
    subnet_id, sg_id = _create_network(ctx)
    role_arn = _create_fargate_execution_role(ctx)

    ce_name = ctx.unique_name("sim2real-batch-ce-")
    ce = batch.create_compute_environment(
        computeEnvironmentName=ce_name,
        type="MANAGED",
        state="ENABLED",
        computeResources={
            "type": "FARGATE",
            "maxvCpus": 1,
            "subnets": [subnet_id],
            "securityGroupIds": [sg_id],
        },
        tags=_MANAGED_TAGS,
    )
    ce_arn = ce["computeEnvironmentArn"]
    ctx.on_cleanup(lambda: _teardown_compute_environment(ctx, ce_name))
    _wait_for_ce_valid(ctx, ce_name)

    queue_name = ctx.unique_name("sim2real-batch-jq-")
    batch.create_job_queue(
        jobQueueName=queue_name,
        priority=1,
        state="ENABLED",
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _teardown_job_queue(ctx, queue_name))
    _wait_for_queue_valid(ctx, queue_name)

    job_def_name = ctx.unique_name("sim2real-batch-jd-")
    job_def = batch.register_job_definition(
        jobDefinitionName=job_def_name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties={
            "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
            "command": ["sleep", "5"],
            "executionRoleArn": role_arn,
            # 2 vCPUs requested against a 1-vCPU compute environment cap: these jobs can
            # never be dispatched, so they stay RUNNABLE forever (no compute cost, no race
            # against a real container actually finishing while we inspect it).
            "resourceRequirements": [
                {"type": "VCPU", "value": "2"},
                {"type": "MEMORY", "value": "4096"},
            ],
            "networkConfiguration": {"assignPublicIp": "ENABLED"},
        },
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(
        lambda: batch.deregister_job_definition(jobDefinition=job_def["jobDefinitionArn"])
    )

    backlog_size = 120
    submit_resp = batch.submit_job(
        jobName=ctx.unique_name("sim2real-batch-array-"),
        jobQueue=queue_name,
        jobDefinition=job_def["jobDefinitionArn"],
        arrayProperties={"size": backlog_size},
    )
    array_job_id = submit_resp["jobId"]
    ctx.on_cleanup(lambda: _terminate_all(ctx, [array_job_id]))

    def probe() -> list[dict[str, Any]]:
        return _list_all_array_children(ctx, array_job_id, job_status="RUNNABLE")

    children = _poll_until(probe, lambda c: len(c) >= backlog_size, timeout_s=180.0, interval_s=5.0)
    assert len(children) == backlog_size, f"expected {backlog_size} RUNNABLE children, got {len(children)}"
    expected_arns = {c["jobArn"] for c in children}
    assert len(expected_arns) == backlog_size, "duplicate child job ARNs reported by ListJobs"

    # GetJobQueueSnapshot is a point-in-time computed view and can lag slightly behind the
    # authoritative per-job state that DescribeJobs/ListJobs already confirmed above, so poll
    # it (bounded) rather than asserting on a single, possibly-stale call.
    def snapshot_probe() -> dict[str, Any]:
        return batch.get_job_queue_snapshot(jobQueue=queue_name)

    snapshot = _poll_until(
        snapshot_probe,
        lambda s: len(s["frontOfQueue"]["jobs"]) == 100,
        timeout_s=120.0,
        interval_s=5.0,
    )
    front_jobs = snapshot["frontOfQueue"]["jobs"]

    assert len(front_jobs) == 100, (
        f"GetJobQueueSnapshot must cap frontOfQueue at the first 100 RUNNABLE jobs "
        f"(backlog was {backlog_size}), got {len(front_jobs)}"
    )
    front_arns = [j["jobArn"] for j in front_jobs]
    assert len(set(front_arns)) == 100, "frontOfQueue contains duplicate job ARNs"
    assert set(front_arns).issubset(expected_arns), (
        "frontOfQueue contains a job ARN that was never submitted to this backlog"
    )

    positions = [j["earliestTimeAtPosition"] for j in front_jobs]
    assert positions == sorted(positions), (
        "frontOfQueue must be ordered by ascending earliestTimeAtPosition for a FIFO queue"
    )


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool],
                 timeout_s: float = 120.0, interval_s: float = 3.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _list_all_array_children(ctx, array_job_id: str, job_status: str) -> list[dict[str, Any]]:
    batch = ctx.client("batch")
    out: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"arrayJobId": array_job_id, "jobStatus": job_status}
        if token:
            kwargs["nextToken"] = token
        resp = batch.list_jobs(**kwargs)
        out.extend(resp.get("jobSummaryList", []))
        token = resp.get("nextToken")
        if not token:
            break
    return out


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


def _create_fargate_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-fgexec-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)

    def probe():
        try:
            return iam.get_role(RoleName=role_name)
        except Exception:
            return None

    _poll_until(probe, lambda r: r is not None, timeout_s=30.0, interval_s=2.0)
    return role_arn


def _wait_for_ce_valid(ctx, ce_name: str, timeout_s: float = 120.0) -> None:
    batch = ctx.client("batch")

    def probe():
        return batch.describe_compute_environments(computeEnvironments=[ce_name])["computeEnvironments"][0]

    result = _poll_until(probe, lambda ce: ce["status"] in ("VALID", "INVALID"), timeout_s=timeout_s, interval_s=3.0)
    assert result["status"] == "VALID", f"compute environment became INVALID: {result.get('statusReason')}"


def _wait_for_queue_valid(ctx, queue_name: str, timeout_s: float = 120.0) -> None:
    batch = ctx.client("batch")

    def probe():
        return batch.describe_job_queues(jobQueues=[queue_name])["jobQueues"][0]

    result = _poll_until(probe, lambda jq: jq["status"] in ("VALID", "INVALID"), timeout_s=timeout_s, interval_s=3.0)
    assert result["status"] == "VALID", f"job queue became INVALID: {result.get('statusReason')}"


def _terminate_all(ctx, job_ids: list[str]) -> None:
    batch = ctx.client("batch")
    for jid in job_ids:
        batch.terminate_job(jobId=jid, reason="sim2real-behavioral-cleanup")


def _teardown_job_queue(ctx, queue_name: str) -> None:
    batch = ctx.client("batch")
    try:
        batch.update_job_queue(jobQueue=queue_name, state="DISABLED")
        _poll_until(
            lambda: batch.describe_job_queues(jobQueues=[queue_name])["jobQueues"][0],
            lambda jq: jq["state"] == "DISABLED" and jq["status"] == "VALID",
            timeout_s=60.0,
            interval_s=3.0,
        )
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    batch.delete_job_queue(jobQueue=queue_name)

    def gone():
        qs = batch.describe_job_queues(jobQueues=[queue_name])["jobQueues"]
        return len(qs) == 0

    _poll_until(gone, lambda g: g, timeout_s=300.0, interval_s=2.0)


def _teardown_compute_environment(ctx, ce_name: str) -> None:
    batch = ctx.client("batch")
    try:
        batch.update_compute_environment(computeEnvironment=ce_name, state="DISABLED")
        _poll_until(
            lambda: batch.describe_compute_environments(computeEnvironments=[ce_name])["computeEnvironments"][0],
            lambda ce: ce["state"] == "DISABLED" and ce["status"] == "VALID",
            timeout_s=60.0,
            interval_s=3.0,
        )
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _delete_compute_environment_and_wait(batch, ce_name)


def _delete_compute_environment_and_wait(batch, name, timeout_s=300.0, interval_s=2.0):
    """DeleteComputeEnvironment, then wait until it is gone. The delete is asynchronous and needs
    the service role until it completes, so returning early lets a later cleanup delete the role
    and strand the environment."""
    retry_deadline = time.monotonic() + timeout_s
    while True:
        if not [ce for ce in batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"]
                if ce.get("status") != "DELETED"]:
            return
        try:
            batch.delete_compute_environment(computeEnvironment=name)
            break
        except ClientError as e:  # still UPDATING, or a job queue being deleted still references it
            if e.response["Error"]["Code"] != "ClientException" or time.monotonic() >= retry_deadline:
                raise
            time.sleep(interval_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        found = batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"]
        if not [ce for ce in found if ce.get("status") != "DELETED"]:
            return
        time.sleep(interval_s)
    raise AssertionError(f"compute environment {name} still present {timeout_s:.0f}s after delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
