"""cancel-running-job-requires-terminate."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-running-job-requires-terminate"
GROUP = "overly-permissive"
SERVICES = ["batch"]

_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CancelJob on a job that has already progressed to RUNNING is a no-op (the job stays
    RUNNING, unaffected); only TerminateJob can stop it. Positive control: CancelJob on a job
    that is still stuck in RUNNABLE (unsatisfiable resource request) does transition it to FAILED."""
    batch = ctx.client("batch")

    subnet_id, sg_id = _create_network(ctx)
    exec_role_arn = _create_execution_role(ctx)
    ce_arn, _ = _create_fargate_compute_environment(ctx, ctx.unique_name("sim2real-batch-ce-"), subnet_id, sg_id, max_vcpus=1)
    jq_arn = _create_job_queue(ctx, ctx.unique_name("sim2real-batch-jq-"), [{"order": 1, "computeEnvironment": ce_arn}])

    # --- Main case: CancelJob must not stop a RUNNING job ---
    running_jobdef = _register_job_definition(
        ctx, ctx.unique_name("sim2real-batch-jd-run-"), exec_role_arn, command=["sleep", "60"]
    )
    running_job_id = batch.submit_job(
        jobName=ctx.unique_name("sim2real-batch-job-run-"), jobQueue=jq_arn, jobDefinition=running_jobdef
    )["jobId"]
    ctx.on_cleanup(lambda: _terminate_job(ctx, running_job_id))
    _poll_until(lambda: _describe_job(ctx, running_job_id)["status"], lambda s: s == "RUNNING", timeout_s=240, interval_s=5)

    batch.cancel_job(jobId=running_job_id, reason="sim2real-behavioral-cancel-running-noop")

    # A CancelJob no-op is asynchronous only in the sense that nothing changes; poll a window
    # to prove the job is not transitioned to FAILED as a delayed side effect of the call.
    for _ in range(6):
        status = _describe_job(ctx, running_job_id)["status"]
        assert status == "RUNNING", f"CancelJob must not affect a RUNNING job, but status became {status}"
        time.sleep(3)

    batch.terminate_job(jobId=running_job_id, reason="sim2real-behavioral-terminate-running")
    final_status = _poll_until(
        lambda: _describe_job(ctx, running_job_id)["status"], lambda s: s in ("FAILED", "SUCCEEDED"), timeout_s=120, interval_s=3
    )
    assert final_status == "FAILED", "TerminateJob must stop a RUNNING job by failing it"

    # --- Positive control: CancelJob DOES stop a job that never left RUNNABLE ---
    # Real AWS Batch rejects SubmitJob outright against a DISABLED job queue (ClientException),
    # so that can't be used to park a job. Instead, request more vCPUs than the compute
    # environment's maxvCpus (1): the job can never be dispatched by the scheduler and stays
    # parked in SUBMITTED/PENDING/RUNNABLE indefinitely, on the same ENABLED queue.
    stuck_jobdef = _register_job_definition(
        ctx, ctx.unique_name("sim2real-batch-jd-stuck-"), exec_role_arn, vcpu="4", memory="8192",
        command=["echo", "unreachable"]
    )
    stuck_job_id = batch.submit_job(
        jobName=ctx.unique_name("sim2real-batch-job-stuck-"), jobQueue=jq_arn, jobDefinition=stuck_jobdef
    )["jobId"]
    ctx.on_cleanup(lambda: _terminate_job(ctx, stuck_job_id))
    _poll_until(
        lambda: _describe_job(ctx, stuck_job_id)["status"],
        lambda s: s in ("SUBMITTED", "PENDING", "RUNNABLE"),
        timeout_s=60,
        interval_s=3,
    )
    batch.cancel_job(jobId=stuck_job_id, reason="sim2real-behavioral-cancel-runnable")
    stuck_final = _poll_until(
        lambda: _describe_job(ctx, stuck_job_id)["status"], lambda s: s in ("FAILED", "STARTING"), timeout_s=60, interval_s=3
    )
    assert stuck_final == "FAILED", "CancelJob on a non-started job must transition it to FAILED"


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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )["Role"]["Arn"]
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
    # No fixed propagation sleep: ECS first assumes this role only when a job is placed, and the
    # compute environment and job queue are each polled to VALID before any job is submitted.
    return role_arn


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


def _retry_refused(call, *, timeout_s=60):
    """Run a Batch teardown call, where "does not exist" means already gone.

    Batch answers ClientException while a dependency drains: retry that every 2 s, then raise.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                return None
            if err["Code"] != "ClientException" or time.monotonic() >= deadline:
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
    _retry_refused(lambda: batch.delete_compute_environment(computeEnvironment=ce_arn), timeout_s=100)


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
    _retry_refused(lambda: batch.delete_job_queue(jobQueue=jq_arn), timeout_s=100)


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
    )
    if consumable_resource_properties:
        kwargs["consumableResourceProperties"] = consumable_resource_properties
    kwargs["tags"] = dict(_MANAGED_TAGS)
    arn = batch.register_job_definition(**kwargs)["jobDefinitionArn"]
    ctx.on_cleanup(lambda: batch.deregister_job_definition(jobDefinition=arn))
    return arn


def _terminate_job(ctx, job_id):
    """Teardown: stop a job this check submitted; a job already terminal is left as it is."""
    batch = ctx.client("batch")
    if _describe_job(ctx, job_id)["status"] not in ("SUCCEEDED", "FAILED"):
        batch.terminate_job(jobId=job_id, reason="sim2real-behavioral-teardown")


def _describe_job(ctx, job_id):
    batch = ctx.client("batch")
    return batch.describe_jobs(jobs=[job_id])["jobs"][0]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
