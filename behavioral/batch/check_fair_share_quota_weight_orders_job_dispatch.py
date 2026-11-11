"""fair-share-quota-weight-orders-job-dispatch."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "fair-share-quota-weight-orders-job-dispatch"
GROUP = "ordering"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK}


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A fair-share policy's weightFactor orders GetJobQueueSnapshot's frontOfQueue: once one share holds
    the queue's sole running Fargate slot, a new job under an idle share ranks ahead of one under the busy share.
    """
    batch = ctx.client("batch")
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")

    subnet_ids, sg_id = _default_vpc_network(ctx, ec2)
    exec_role_arn = _create_execution_role(ctx, iam)
    policy_arn = _create_fairshare_policy(ctx, batch, weights={"busy": 10.0, "idle": 0.1})
    ce_arn, ce_name = _create_fargate_compute_environment(ctx, batch, subnet_ids, sg_id, max_vcpus=1)
    jobdef_arn = _register_fargate_jobdef(ctx, batch, exec_role_arn, vcpu="1", memory_mib="2048")
    queue_arn, queue_name = _create_job_queue(ctx, batch, ce_arn, policy_arn)

    # Occupy the queue's sole 1-vCPU Fargate slot with a long-running job under "busy".
    runner_name = ctx.unique_name("sim2real-batch-runner-")
    # A queue with a fairsharePolicy scheduling policy requires an explicit scheduling
    # priority on every submission; equal across all three jobs so weightFactor alone
    # drives the ordering under test.
    runner = batch.submit_job(
        jobName=runner_name,
        jobQueue=queue_arn,
        jobDefinition=jobdef_arn,
        shareIdentifier="busy",
        schedulingPriorityOverride=0,
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda jid=runner["jobId"]: _stop_job(batch, jid))
    _poll_job_status(batch, runner["jobId"], {"RUNNING"}, {"FAILED", "SUCCEEDED"}, timeout_s=240.0)

    # Now submit one probe job under each share; both must wait since capacity is full.
    busy_probe = batch.submit_job(
        jobName=ctx.unique_name("sim2real-batch-busyprobe-"),
        jobQueue=queue_arn,
        jobDefinition=jobdef_arn,
        shareIdentifier="busy",
        schedulingPriorityOverride=0,
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda jid=busy_probe["jobId"]: _stop_job(batch, jid))
    idle_probe = batch.submit_job(
        jobName=ctx.unique_name("sim2real-batch-idleprobe-"),
        jobQueue=queue_arn,
        jobDefinition=jobdef_arn,
        shareIdentifier="idle",
        schedulingPriorityOverride=0,
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda jid=idle_probe["jobId"]: _stop_job(batch, jid))

    expected = {busy_probe["jobArn"], idle_probe["jobArn"]}
    front = _poll_front_of_queue(batch, queue_arn, expected_arns=expected, timeout_s=90.0)
    positions = {entry["jobArn"]: idx for idx, entry in enumerate(front)}
    assert idle_probe["jobArn"] in positions and busy_probe["jobArn"] in positions, (
        f"expected both probe jobs {sorted(expected)} in frontOfQueue, got {sorted(positions)}"
    )
    assert positions[idle_probe["jobArn"]] < positions[busy_probe["jobArn"]], (
        "the idle-share probe (lower weightFactor, no existing usage) should be ranked "
        f"ahead of the busy-share probe; got positions {positions}"
    )


# ===== helpers =====

def _poll_until(probe, predicate, *, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _default_vpc_network(ctx, ec2):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError("no shared network VPC available to host a Fargate compute environment")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    if not subnets:
        raise AssertionError("shared network has no subnets available for a Fargate compute environment")
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    ).get("SecurityGroups", [])
    if not sgs:
        raise AssertionError("shared network has no default security group")
    return subnet_ids, sgs[0]["GroupId"]


def _create_execution_role(ctx, iam):
    import json

    role_name = ctx.unique_name("sim2real-batch-execrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ecs-tasks.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )
    role_arn = resp["Role"]["Arn"]
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
    )

    def _cleanup():
        try:
            iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
            )
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


def _create_fairshare_policy(ctx, batch, weights):
    name = ctx.unique_name("sim2real-batch-sp-")
    resp = batch.create_scheduling_policy(
        name=name,
        fairsharePolicy={
            "shareDecaySeconds": 60,
            "computeReservation": 0,
            "shareDistribution": [
                {"shareIdentifier": sid, "weightFactor": w} for sid, w in weights.items()
            ],
        },
        tags=_MANAGED_TAGS,
    )
    arn = resp["arn"]
    ctx.on_cleanup(lambda: _delete_scheduling_policy(batch, arn))
    return arn


def _retry_client_exception(call, timeout_s=120):
    """Retry a delete Batch refuses with ClientException while a dependency releases, every 2 s; then raise."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                return None
            if err["Code"] != "ClientException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _delete_scheduling_policy(batch, arn):
    _retry_client_exception(lambda: batch.delete_scheduling_policy(arn=arn), timeout_s=90)


def _create_fargate_compute_environment(ctx, batch, subnet_ids, sg_id, max_vcpus):
    ce_name = ctx.unique_name("sim2real-batch-ce-")
    resp = batch.create_compute_environment(
        computeEnvironmentName=ce_name,
        type="MANAGED",
        state="ENABLED",
        computeResources={
            "type": "FARGATE",
            "maxvCpus": max_vcpus,
            "subnets": subnet_ids,
            "securityGroupIds": [sg_id],
        },
        tags=_MANAGED_TAGS,
    )
    ce_arn = resp["computeEnvironmentArn"]

    def _wait_valid():
        d = batch.describe_compute_environments(computeEnvironments=[ce_name])
        envs = d.get("computeEnvironments", [])
        return envs[0] if envs else None

    env = _poll_until(_wait_valid, lambda e: e is not None and e["status"] in ("VALID", "INVALID"), timeout_s=120.0, interval_s=3.0)
    assert env["status"] == "VALID", env.get("statusReason")

    ctx.on_cleanup(lambda: _delete_compute_environment(batch, ce_name))
    return ce_arn, ce_name


def _delete_compute_environment(batch, ce_name):
    try:
        batch.update_compute_environment(computeEnvironment=ce_name, state="DISABLED")
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _retry_client_exception(lambda: batch.delete_compute_environment(computeEnvironment=ce_name), timeout_s=150)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        d = batch.describe_compute_environments(computeEnvironments=[ce_name])
        envs = d.get("computeEnvironments", [])
        if not envs or envs[0]["status"] == "DELETED":
            return
        time.sleep(5)


def _register_fargate_jobdef(ctx, batch, exec_role_arn, vcpu, memory_mib):
    name = ctx.unique_name("sim2real-batch-jobdef-")
    resp = batch.register_job_definition(
        jobDefinitionName=name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties={
            "image": "public.ecr.aws/docker/library/busybox:1.36",
            "resourceRequirements": [
                {"type": "VCPU", "value": vcpu},
                {"type": "MEMORY", "value": memory_mib},
            ],
            "executionRoleArn": exec_role_arn,
            "command": ["sleep", "45"],
            "networkConfiguration": {"assignPublicIp": "ENABLED"},
        },
        tags=_MANAGED_TAGS,
    )
    arn = resp["jobDefinitionArn"]
    ctx.on_cleanup(lambda: _deregister_safely(batch, arn))
    return arn


def _deregister_safely(batch, jobdef_arn):
    batch.deregister_job_definition(jobDefinition=jobdef_arn)


def _create_job_queue(ctx, batch, ce_arn, policy_arn):
    name = ctx.unique_name("sim2real-batch-jq-")
    resp = batch.create_job_queue(
        jobQueueName=name,
        state="ENABLED",
        priority=1,
        schedulingPolicyArn=policy_arn,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
        tags=_MANAGED_TAGS,
    )
    arn = resp["jobQueueArn"]

    def _wait_valid():
        d = batch.describe_job_queues(jobQueues=[name])
        queues = d.get("jobQueues", [])
        return queues[0] if queues else None

    queue = _poll_until(_wait_valid, lambda q: q is not None and q["status"] in ("VALID", "INVALID"), timeout_s=60.0, interval_s=2.0)
    assert queue["status"] == "VALID", queue.get("statusReason")

    ctx.on_cleanup(lambda: _delete_job_queue(batch, arn, name))
    return arn, name


def _delete_job_queue(batch, jq_arn, jq_name):
    try:
        batch.update_job_queue(jobQueue=jq_arn, state="DISABLED")
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _retry_client_exception(lambda: batch.delete_job_queue(jobQueue=jq_arn), timeout_s=150)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        d = batch.describe_job_queues(jobQueues=[jq_name])
        queues = d.get("jobQueues", [])
        if not queues or queues[0]["status"] == "DELETED":
            return
        time.sleep(5)


def _stop_job(batch, job_id):
    jobs = batch.describe_jobs(jobs=[job_id]).get("jobs", [])
    status = jobs[0]["status"] if jobs else None
    if status in ("STARTING", "RUNNING"):
        batch.terminate_job(jobId=job_id, reason="sim2real-cleanup")
    else:
        batch.cancel_job(jobId=job_id, reason="sim2real-cleanup")
    deadline = time.monotonic() + 90
    terminal = {"SUCCEEDED", "FAILED"}
    while time.monotonic() < deadline:
        jobs = batch.describe_jobs(jobs=[job_id]).get("jobs", [])
        if not jobs or jobs[0]["status"] in terminal:
            return
        time.sleep(4)


def _poll_job_status(batch, job_id, ok_statuses, bad_statuses, timeout_s=240.0):
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        jobs = batch.describe_jobs(jobs=[job_id]).get("jobs", [])
        if jobs:
            last_status = jobs[0]["status"]
            if last_status in ok_statuses:
                return last_status
            if last_status in bad_statuses:
                raise AssertionError(
                    f"job {job_id} reached unexpected status {last_status}: "
                    f"{jobs[0].get('statusReason')}"
                )
        time.sleep(4)
    raise AssertionError(f"job {job_id} never reached {ok_statuses} within {timeout_s}s (last={last_status})")


def _poll_front_of_queue(batch, queue_arn, expected_arns, timeout_s=90.0):
    def _probe():
        resp = batch.get_job_queue_snapshot(jobQueue=queue_arn)
        return resp.get("frontOfQueue", {}).get("jobs", [])

    def _has_all(jobs):
        seen = {entry["jobArn"] for entry in jobs}
        return expected_arns.issubset(seen)

    return _poll_until(_probe, _has_all, timeout_s=timeout_s, interval_s=3.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
