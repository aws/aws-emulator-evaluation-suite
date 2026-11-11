"""get-job-queue-snapshot-unknown-queue-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-job-queue-snapshot-unknown-queue-rejected"
GROUP = "data-plane"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetJobQueueSnapshot against a job queue name that was never created is rejected with
    ClientException, leaves no phantom queue behind, and a real queue's snapshot still
    succeeds and reflects its actual RUNNABLE job (positive control in the same run).
    """
    batch = ctx.client("batch")
    subnet_id, sg_id = _owned_subnet_and_sg(ctx)
    role_arn = _create_fargate_execution_role(ctx)

    ce_name = ctx.unique_name("sim2real-batch-ce3-")
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
        tags={"sim2real-check": CHECK},
    )
    ce_arn = ce["computeEnvironmentArn"]
    ctx.on_cleanup(lambda: _teardown_compute_environment(ctx, ce_name))
    _wait_for_ce_valid(ctx, ce_name)

    jq_name = ctx.unique_name("sim2real-batch-jq3-")
    batch.create_job_queue(
        jobQueueName=jq_name,
        priority=1,
        state="ENABLED",
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _teardown_job_queue(ctx, jq_name))
    _wait_for_queue_valid(ctx, jq_name)

    jd_name = ctx.unique_name("sim2real-batch-jd3-")
    job_def = batch.register_job_definition(
        jobDefinitionName=jd_name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties={
            "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
            "command": ["sleep", "5"],
            "executionRoleArn": role_arn,
            "resourceRequirements": [
                {"type": "VCPU", "value": "2"},
                {"type": "MEMORY", "value": "4096"},
            ],
            "networkConfiguration": {"assignPublicIp": "ENABLED"},
        },
        tags={"sim2real-check": CHECK},
    )
    jd_arn = job_def["jobDefinitionArn"]
    ctx.on_cleanup(lambda: batch.deregister_job_definition(jobDefinition=jd_arn))

    submit_resp = batch.submit_job(
        jobName=ctx.unique_name("sim2real-batch-job-"), jobQueue=jq_name, jobDefinition=jd_arn
    )
    job_id = submit_resp["jobId"]
    job_arn = submit_resp["jobArn"]
    ctx.on_cleanup(lambda: _terminate_all(ctx, [job_id]))
    _poll_until(
        lambda: batch.describe_jobs(jobs=[job_id])["jobs"][0]["status"],
        lambda s: s == "RUNNABLE",
        timeout_s=90.0,
        interval_s=3.0,
    )

    bogus_name = ctx.unique_name("sim2real-batch-missing-jq-")
    code, message = _error(lambda: batch.get_job_queue_snapshot(jobQueue=bogus_name))
    assert code == "ClientException", f"expected ClientException, got {code}"
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    expected_message = f"arn:aws:batch:{ctx.region}:{account_id}:job-queue/{bogus_name} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # (b) no side effect: the bogus name must not now exist as a real job queue
    existing_names = {q["jobQueueName"] for q in batch.describe_job_queues()["jobQueues"]}
    assert bogus_name not in existing_names, (
        f"expected {bogus_name!r} to remain absent from job queues, but found it in {existing_names}"
    )

    # (c) positive control: the real queue's snapshot still works correctly
    def snapshot_probe() -> dict[str, Any]:
        return batch.get_job_queue_snapshot(jobQueue=jq_name)

    snap = _poll_until(
        snapshot_probe,
        lambda s: job_arn in {j["jobArn"] for j in s["frontOfQueue"]["jobs"]},
        timeout_s=90.0,
        interval_s=5.0,
    )
    front_arns = {j["jobArn"] for j in snap["frontOfQueue"]["jobs"]}
    assert job_arn in front_arns, f"expected {job_arn} in {front_arns}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises directly."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _owned_subnet_and_sg(ctx) -> tuple[str, str]:
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
    role_name = ctx.unique_name("sim2real-batch-fgexec4-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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

    try:
        _poll_until(gone, lambda g: g, timeout_s=90.0, interval_s=3.0)
    except AssertionError:
        pass


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
    batch.delete_compute_environment(computeEnvironment=ce_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

