"""job-queue-snapshot-capacity-usage-reflects-real-running-job."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "job-queue-snapshot-capacity-usage-reflects-real-running-job"
GROUP = "data-plane"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """With three 1-vCPU jobs on a 1-vCPU compute environment (one RUNNING, two RUNNABLE per
    DescribeJobs), GetJobQueueSnapshot's frontOfQueue holds exactly the two RUNNABLE jobs and not
    the RUNNING one, and queueUtilization.totalCapacityUsage reports a VCPU quantity of 1."""
    batch = ctx.client("batch")
    subnet_id, sg_id = _owned_subnet_and_sg(ctx)
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
        tags=dict(_MANAGED_TAGS),
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
        tags=dict(_MANAGED_TAGS),
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
            "command": ["sleep", "90"],
            "executionRoleArn": role_arn,
            "resourceRequirements": [
                {"type": "VCPU", "value": "1"},
                {"type": "MEMORY", "value": "2048"},
            ],
            "networkConfiguration": {"assignPublicIp": "ENABLED"},
        },
        tags=dict(_MANAGED_TAGS),
    )
    ctx.on_cleanup(
        lambda: batch.deregister_job_definition(jobDefinition=job_def["jobDefinitionArn"])
    )

    job_ids = []
    for i in range(3):
        resp = batch.submit_job(
            jobName=ctx.unique_name(f"sim2real-batch-job{i}-"),
            jobQueue=queue_name,
            jobDefinition=job_def["jobDefinitionArn"],
        )
        job_ids.append(resp["jobId"])
    ctx.on_cleanup(lambda: _terminate_all(ctx, job_ids))

    def probe() -> list[dict[str, Any]]:
        return batch.describe_jobs(jobs=job_ids)["jobs"]

    def settled(jobs: list[dict[str, Any]]) -> bool:
        statuses = [j["status"] for j in jobs]
        return statuses.count("RUNNING") == 1 and statuses.count("RUNNABLE") == 2

    jobs = _poll_until(probe, settled, timeout_s=240.0, interval_s=5.0)
    running_arns = {j["jobArn"] for j in jobs if j["status"] == "RUNNING"}
    runnable_arns = {j["jobArn"] for j in jobs if j["status"] == "RUNNABLE"}
    assert len(running_arns) == 1 and len(runnable_arns) == 2, (
        f"expected exactly 1 RUNNING and 2 RUNNABLE, got statuses "
        f"{[j['status'] for j in jobs]!r}"
    )

    # The snapshot is an eventually consistent view of the scheduler: poll it, bounded, until
    # it shows the RUNNABLE set DescribeJobs reports. The RUNNING job sleeps 90s, so the split
    # holds for the whole window; it is re-read afterwards to prove it still held.
    deadline = time.monotonic() + 45.0
    while True:
        snapshot = batch.get_job_queue_snapshot(jobQueue=queue_name)
        front_arns = {j["jobArn"] for j in snapshot["frontOfQueue"]["jobs"]}
        if front_arns == runnable_arns or time.monotonic() >= deadline:
            break
        time.sleep(3.0)
    after = {j["jobArn"]: j["status"] for j in probe()}
    assert {a for a, st in after.items() if st == "RUNNABLE"} == runnable_arns, (
        f"the RUNNING/RUNNABLE split changed while the snapshot was read: {after!r}"
    )

    assert front_arns == runnable_arns, (
        f"frontOfQueue {front_arns} does not match the actually-RUNNABLE set {runnable_arns}"
    )
    assert not (front_arns & running_arns), "the RUNNING job must not appear in frontOfQueue"

    total_usage = snapshot["queueUtilization"]["totalCapacityUsage"]
    vcpu_entries = [u for u in total_usage if u["capacityUnit"] == "VCPU"]
    assert vcpu_entries, f"expected a VCPU capacity usage entry, got {total_usage!r}"
    assert vcpu_entries[0]["quantity"] == 1, (
        f"expected 1 vCPU of usage for the single RUNNING job, got {vcpu_entries[0]!r}"
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


def _owned_subnet_and_sg(ctx) -> tuple[str, str]:
    """Create this run's own internet-routable VPC with one public subnet; return
    (subnet_id, the VPC's default security group id) for the Fargate compute environment."""
    ec2 = ctx.client("ec2")
    tag_list = [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.184.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag_list}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.184.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag_list}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": tag_list}]
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(
        lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
    )
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"][0][
        "RouteTableId"
    ]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    assert sgs, f"VPC {vpc_id} has no default security group"
    return subnet_id, sgs[0]["GroupId"]


# Teardown-only: Fargate ENIs detach some time after their tasks stop, so each network delete
# waits for the ENIs in its scope to drain before retrying DependencyViolation, bounded.
_NET_TEARDOWN_S = 600.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id"}


def _delete_net(client, op, **ident):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + _NET_TEARDOWN_S
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while flt and client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]:
        if time.monotonic() >= deadline:
            break
        time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(10)


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
        Tags=_tags_kv(),
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
