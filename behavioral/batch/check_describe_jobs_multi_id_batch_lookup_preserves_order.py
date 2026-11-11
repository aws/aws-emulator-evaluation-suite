"""describe-jobs-multi-id-batch-lookup-preserves-order."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-jobs-multi-id-batch-lookup-preserves-order"
GROUP = "ordering"
SERVICES = ["batch"]

_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeJobs with a shuffled list of job IDs returns exactly one correctly correlated record
    per requested ID (none dropped or duplicated, jobId/jobName pairing intact); the response order
    is not a documented contract, so only the complete set is asserted.
    """
    batch = ctx.client("batch")

    subnet_id, sg_id = _default_subnet_and_sg(ctx)
    exec_role_arn = _create_execution_role(ctx)
    ce_arn, _ = _create_fargate_compute_environment(ctx, ctx.unique_name("sim2real-batch-ce-"), subnet_id, sg_id, max_vcpus=1)
    # Real AWS Batch rejects SubmitJob against a DISABLED job queue with a ClientException, so
    # the queue must stay ENABLED. DescribeJobs' batch-lookup correctness doesn't depend on the
    # jobs staying pending; jobName/jobId correlation is deterministic regardless of how quickly
    # the jobs progress.
    jq_arn = _create_job_queue(ctx, ctx.unique_name("sim2real-batch-jq-"), [{"order": 1, "computeEnvironment": ce_arn}])
    jobdef_arn = _register_job_definition(ctx, ctx.unique_name("sim2real-batch-jd-"), exec_role_arn, command=["echo", "hi"])

    # Submit three jobs in a known order with distinguishable names.
    names = [ctx.unique_name(f"sim2real-batch-job-{i}-") for i in range(3)]
    job_ids = [
        batch.submit_job(jobName=n, jobQueue=jq_arn, jobDefinition=jobdef_arn)["jobId"] for n in names
    ]
    name_by_id = dict(zip(job_ids, names))

    # Query with a deliberately shuffled, non-monotonic ID order: [2, 0, 1].
    shuffled_ids = [job_ids[2], job_ids[0], job_ids[1]]
    resp = batch.describe_jobs(jobs=shuffled_ids)["jobs"]

    assert len(resp) == 3, f"expected 3 job details for {shuffled_ids}, got {len(resp)}: {resp}"
    returned_ids = [j["jobId"] for j in resp]
    assert sorted(returned_ids) == sorted(shuffled_ids), (
        f"DescribeJobs must return exactly the requested IDs (no drops/dupes), "
        f"got {returned_ids} for input {shuffled_ids}"
    )
    for job in resp:
        assert job["jobId"] in name_by_id, (
            f"DescribeJobs returned jobId {job['jobId']!r} that was never submitted; "
            f"submitted ids were {list(name_by_id)}"
        )
        assert job["jobName"] == name_by_id[job["jobId"]], (
            f"job {job['jobId']} returned with wrong jobName {job['jobName']!r}, "
            f"expected {name_by_id[job['jobId']]!r}"
        )

    # A second, differently-shuffled query over the same IDs must also come back complete and
    # correctly correlated (again, without assuming any particular response ordering).
    shuffled_ids_2 = [job_ids[1], job_ids[2], job_ids[0]]
    resp_2 = batch.describe_jobs(jobs=shuffled_ids_2)["jobs"]
    returned_ids_2 = [j["jobId"] for j in resp_2]
    assert sorted(returned_ids_2) == sorted(shuffled_ids_2), (
        f"DescribeJobs must return exactly the requested IDs (no drops/dupes) on the second, "
        f"differently-shuffled query too, got {returned_ids_2} for input {shuffled_ids_2}"
    )
    for job in resp_2:
        assert job["jobName"] == name_by_id[job["jobId"]], (
            f"job {job['jobId']} returned with wrong jobName {job['jobName']!r} on the second query, "
            f"expected {name_by_id[job['jobId']]!r}"
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


def _default_subnet_and_sg(ctx):

    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available for an AWS Batch Fargate compute environment")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnets in the shared network")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    return subnets[0]["SubnetId"], sgs[0]["GroupId"]


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
        RoleName=role_name, AssumeRolePolicyDocument=trust, Tags=_tags_kv()
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
    _retry_client_exception(lambda: batch.delete_compute_environment(computeEnvironment=ce_arn))


def _create_job_queue(ctx, name, ce_order, priority=1, state="ENABLED"):
    batch = ctx.client("batch")
    jq_arn = batch.create_job_queue(
        jobQueueName=name,
        state=state,
        priority=priority,
        computeEnvironmentOrder=ce_order,
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
    _retry_client_exception(lambda: batch.delete_job_queue(jobQueue=jq_arn))


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
