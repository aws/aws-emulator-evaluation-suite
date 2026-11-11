"""job-queue-priority-scheduling-order-enforced."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "job-queue-priority-scheduling-order-enforced"
GROUP = "server-side"
SERVICES = ["batch"]

_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """When two job queues share the same (capacity-constrained) compute environment, a job
    submitted to the higher-priority queue is dispatched ahead of an equally-eligible job that
    has been waiting on the lower-priority queue since capacity freed up for both at once."""
    batch = ctx.client("batch")

    subnet_id, sg_id = _create_network(ctx)
    exec_role_arn = _create_execution_role(ctx)
    # Exactly one 1-vCPU Fargate slot: only one job of this size can run at a time.
    ce_arn, _ = _create_fargate_compute_environment(ctx, ctx.unique_name("sim2real-batch-ce-"), subnet_id, sg_id, max_vcpus=1)

    jq_low_arn = _create_job_queue(ctx, ctx.unique_name("sim2real-batch-jqlow-"), [{"order": 1, "computeEnvironment": ce_arn}], priority=1)
    jq_high_arn = _create_job_queue(ctx, ctx.unique_name("sim2real-batch-jqhigh-"), [{"order": 1, "computeEnvironment": ce_arn}], priority=100)

    filler_jobdef = _register_job_definition(
        ctx, ctx.unique_name("sim2real-batch-jd-filler-"), exec_role_arn, vcpu="1", memory="2048", command=["sleep", "30"]
    )
    probe_jobdef = _register_job_definition(
        ctx, ctx.unique_name("sim2real-batch-jd-probe-"), exec_role_arn, vcpu="1", memory="2048", command=["echo", "probe"]
    )

    # Occupy the single slot with a filler job on the low-priority queue.
    filler_job_id = batch.submit_job(
        jobName=ctx.unique_name("sim2real-batch-job-filler-"), jobQueue=jq_low_arn, jobDefinition=filler_jobdef
    )["jobId"]
    _poll_until(lambda: _describe_job(ctx, filler_job_id)["status"], lambda s: s == "RUNNING", timeout_s=240, interval_s=5)

    # With the slot full, submit a low-priority-queue job (B) first, then a high-priority-queue
    # job (C) second - if placement only followed submission order, B would win the free slot.
    job_b_id = batch.submit_job(jobName=ctx.unique_name("sim2real-batch-job-lowq-"), jobQueue=jq_low_arn, jobDefinition=probe_jobdef)["jobId"]
    job_c_id = batch.submit_job(jobName=ctx.unique_name("sim2real-batch-job-highq-"), jobQueue=jq_high_arn, jobDefinition=probe_jobdef)["jobId"]

    _poll_until(lambda: _describe_job(ctx, job_b_id)["status"], lambda s: s == "RUNNABLE", timeout_s=60, interval_s=3)
    _poll_until(lambda: _describe_job(ctx, job_c_id)["status"], lambda s: s == "RUNNABLE", timeout_s=60, interval_s=3)

    # Wait for the filler to finish and free the single slot, then watch which of B/C moves first.
    _poll_until(lambda: _describe_job(ctx, filler_job_id)["status"], lambda s: s == "SUCCEEDED", timeout_s=120, interval_s=3)

    winner = _poll_until(
        lambda: {
            "b": _describe_job(ctx, job_b_id)["status"] not in ("RUNNABLE",),
            "c": _describe_job(ctx, job_c_id)["status"] not in ("RUNNABLE",),
        },
        lambda snap: snap["b"] or snap["c"],
        timeout_s=180,
        interval_s=2,
    )

    assert winner["c"] is True, "the high-priority queue's job should be the first to leave RUNNABLE"
    assert winner["b"] is False, "the low-priority queue's job should still be waiting when the high-priority job advances"

    # Both eventually complete once capacity cycles through them.
    final_b = _poll_until(lambda: _describe_job(ctx, job_b_id)["status"], lambda s: s in ("SUCCEEDED", "FAILED"), timeout_s=180, interval_s=5)
    final_c = _poll_until(lambda: _describe_job(ctx, job_c_id)["status"], lambda s: s in ("SUCCEEDED", "FAILED"), timeout_s=180, interval_s=5)
    assert final_b == "SUCCEEDED" and final_c == "SUCCEEDED", (
        f"expected both jobs to reach SUCCEEDED once capacity cycled through them, got b={final_b!r} c={final_c!r}"
    )


# ===== helpers =====

def _poll_until(probe, predicate, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


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


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-exec-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust, Tags=_tags_kv())["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_EXEC_POLICY_ARN)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=_EXEC_POLICY_ARN)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _retry_until(fn, timeout_s=60.0, interval_s=5.0, reason=""):
    """Bounded retry for a call that can transiently fail while a just-created IAM role
    has not yet propagated to Batch/ECS -- never a blind sleep, and it still raises if the
    call keeps failing once the deadline passes."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"{reason}: still failing after {timeout_s}s: {last_exc}") from last_exc


def _create_fargate_compute_environment(ctx, name, subnet_id, sg_id, max_vcpus=4):
    batch = ctx.client("batch")
    ce_arn = batch.create_compute_environment(
        computeEnvironmentName=name,
        type="MANAGED",
        state="ENABLED",
        computeResources={
            "type": "FARGATE",
            "maxvCpus": max_vcpus,
            "subnets": [subnet_id],
            "securityGroupIds": [sg_id],
        },
        tags=dict(_MANAGED_TAGS),
    )["computeEnvironmentArn"]
    ctx.on_cleanup(lambda: _delete_compute_environment(ctx, ce_arn))
    detail = _poll_until(
        lambda: batch.describe_compute_environments(computeEnvironments=[ce_arn])["computeEnvironments"][0],
        lambda d: d["status"] in ("VALID", "INVALID"),
        timeout_s=120,
    )
    assert detail["status"] == "VALID", f"compute environment failed to become VALID: {detail.get('statusReason')}"
    return ce_arn, detail.get("ecsClusterArn")


def _retry_client_exception(call, timeout_s=120):
    """Retry a delete Batch refuses with ClientException while a dependency releases, every 2 s; then raise."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClientException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _delete_compute_environment(ctx, ce_arn):
    batch = ctx.client("batch")
    try:
        batch.update_compute_environment(computeEnvironment=ce_arn, state="DISABLED")
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _poll_until(
        lambda: batch.describe_compute_environments(computeEnvironments=[ce_arn])["computeEnvironments"][0]["status"],
        lambda s: s == "VALID",
        timeout_s=120,
    )
    _retry_client_exception(lambda: batch.delete_compute_environment(computeEnvironment=ce_arn), timeout_s=100)


def _create_job_queue(ctx, name, ce_order, priority=1, state="ENABLED"):
    batch = ctx.client("batch")
    jq_arn = batch.create_job_queue(
        jobQueueName=name, state=state, priority=priority, computeEnvironmentOrder=ce_order,
        tags=dict(_MANAGED_TAGS),
    )["jobQueueArn"]
    ctx.on_cleanup(lambda: _delete_job_queue(ctx, jq_arn))
    detail = _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[jq_arn])["jobQueues"][0],
        lambda d: d["status"] in ("VALID", "INVALID"),
        timeout_s=120,
    )
    assert detail["status"] == "VALID", f"job queue failed to become VALID: {detail.get('statusReason')}"
    return jq_arn


def _delete_job_queue(ctx, jq_arn):
    batch = ctx.client("batch")
    try:
        batch.update_job_queue(jobQueue=jq_arn, state="DISABLED")
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[jq_arn])["jobQueues"][0]["status"],
        lambda s: s == "VALID",
        timeout_s=120,
    )
    _retry_client_exception(lambda: batch.delete_job_queue(jobQueue=jq_arn), timeout_s=100)


def _register_job_definition(ctx, name, exec_role_arn, vcpu="0.25", memory="512", command=None,
                              consumable_resource_properties=None):
    batch = ctx.client("batch")
    kwargs = dict(
        jobDefinitionName=name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties={
            "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
            "resourceRequirements": [{"type": "VCPU", "value": vcpu}, {"type": "MEMORY", "value": memory}],
            "command": command or ["echo", "hello"],
            "networkConfiguration": {"assignPublicIp": "ENABLED"},
            "executionRoleArn": exec_role_arn,
        },
        tags=dict(_MANAGED_TAGS),
    )
    if consumable_resource_properties:
        kwargs["consumableResourceProperties"] = consumable_resource_properties
    arn = _retry_until(
        lambda: batch.register_job_definition(**kwargs)["jobDefinitionArn"],
        timeout_s=60.0,
        interval_s=5.0,
        reason=(
            f"registering a job definition against execution role {exec_role_arn} "
            f"(the role may not yet be propagated for Batch to accept it)"
        ),
    )
    ctx.on_cleanup(lambda: batch.deregister_job_definition(jobDefinition=arn))
    return arn


def _describe_job(ctx, job_id):
    batch = ctx.client("batch")
    return batch.describe_jobs(jobs=[job_id])["jobs"][0]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
