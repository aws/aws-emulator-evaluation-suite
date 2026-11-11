"""describe-jobs-unknown-id-returns-empty."""

from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "describe-jobs-unknown-id-returns-empty"
GROUP = 'error-semantics'
SERVICES = ['batch']

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_ECS_TASK_EXECUTION_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeJobs omits an unknown jobId rather than erroring: alone it returns [], and mixed with
    a real submitted job (the positive control against an always-empty answer) it returns exactly the real job.
    """
    bat = ctx.client("batch")

    subnets, sg_id = _default_vpc_networking(ctx)
    service_role_arn = _service_linked_role_arn(ctx)
    exec_role_arn = _create_execution_role(ctx)

    ce_name, ce_arn = _create_fargate_ce(ctx, bat, subnets, sg_id, service_role_arn)
    _wait_ce_status(bat, ce_name, {"VALID"}, timeout_s=180, interval_s=5)

    jq_name, jq_arn = _create_job_queue(ctx, bat, ce_arn)
    _wait_jq_status(bat, jq_name, {"VALID"}, timeout_s=120, interval_s=3)

    jd_name, jd_revision = _register_job_definition(ctx, bat, exec_role_arn)

    unknown_id = str(uuid.uuid4())
    resp = bat.describe_jobs(jobs=[unknown_id]).get("jobs")
    assert resp == [], f"expected empty jobs list for unknown id, got {resp!r}"

    job_name = ctx.unique_name("sim2real-behav-job-")
    real_job_id = bat.submit_job(
        jobName=job_name, jobQueue=jq_name, jobDefinition=f"{jd_name}:{jd_revision}"
    )["jobId"]
    ctx.on_cleanup(lambda: _swallow(lambda: bat.terminate_job(jobId=real_job_id, reason="behavioral-test-cleanup")))

    mixed = bat.describe_jobs(jobs=[real_job_id, unknown_id])["jobs"]
    returned_ids = [j["jobId"] for j in mixed]
    assert returned_ids == [real_job_id], (
        f"expected DescribeJobs([real, unknown]) to return exactly the real job and "
        f"silently omit the unknown one, got {returned_ids!r}"
    )
    assert mixed[0]["jobName"] == job_name, f"expected jobName {job_name!r}, got {mixed[0]['jobName']!r}"


# ===== helpers =====

def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] != "NoSuchEntity"
            and not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""))
        ):
            raise


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last result={last!r}")


def _describe_ce(bat, name):
    envs = bat.describe_compute_environments(computeEnvironments=[name]).get("computeEnvironments", [])
    return envs[0] if envs else None


def _describe_jq(bat, name):
    qs = bat.describe_job_queues(jobQueues=[name]).get("jobQueues", [])
    return qs[0] if qs else None


def _wait_ce_status(bat, name, statuses, timeout_s=180, interval_s=5):
    return _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is not None and ce.get("status") in statuses,
        timeout_s=timeout_s, interval_s=interval_s,
        description=f"compute environment {name} status in {sorted(statuses)}",
    )


def _wait_jq_status(bat, name, statuses, timeout_s=120, interval_s=3):
    return _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is not None and jq.get("status") in statuses,
        timeout_s=timeout_s, interval_s=interval_s,
        description=f"job queue {name} status in {sorted(statuses)}",
    )


def _default_vpc_networking(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region; cannot build a Fargate compute environment")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    subnet_ids = [s["SubnetId"] for s in subnets if s.get("AvailableIpAddressCount", 0) > 0]
    if not subnet_ids:
        raise AssertionError(f"shared network {vpc_id} has no usable subnets")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    ).get("SecurityGroups", [])
    if not sgs:
        raise AssertionError(f"shared network {vpc_id} has no default security group")
    return subnet_ids[:3], sgs[0]["GroupId"]


def _service_linked_role_arn(ctx):
    """The account's AWSServiceRoleForBatch SLR (required for a MANAGED CE). Shared: never deleted."""
    iam = ctx.client("iam")
    try:
        return iam.get_role(RoleName="AWSServiceRoleForBatch")["Role"]["Arn"]
    except Exception:
        pass
    try:
        resp = iam.create_service_linked_role(AWSServiceName="batch.amazonaws.com")
    except Exception as exc:
        raise AssertionError(f"cannot resolve the Batch service-linked role: {exc}") from exc
    arn = resp["Role"]["Arn"]
    # Bounded wait for IAM's own read-after-create window rather than a blind sleep.
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName="AWSServiceRoleForBatch")
            return arn
        except Exception:
            time.sleep(2)
    raise AssertionError("AWSServiceRoleForBatch did not become gettable within 30s of creation")


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-batch-exec-")
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
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_ECS_TASK_EXECUTION_POLICY)

    def _cleanup():
        _swallow(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_ECS_TASK_EXECUTION_POLICY))
        _swallow(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    # No propagation wait needed: the check never waits for the submitted job to actually
    # be launched by ECS, only for DescribeJobs to report it, so the role's assumability
    # is irrelevant to what this check asserts.
    return role_arn


def _create_fargate_ce(ctx, bat, subnets, sg_id, service_role_arn, max_vcpus=1):
    name = ctx.unique_name("sim2real-behav-ce-fg-")
    # Bounded retry, not a blind sleep: a just-created service-linked role can still be
    # too fresh for Batch to accept as serviceRole for a few seconds after IAM says it exists.
    deadline = time.monotonic() + 60.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = bat.create_compute_environment(
                computeEnvironmentName=name,
                type="MANAGED",
                state="ENABLED",
                serviceRole=service_role_arn,
                computeResources={
                    "type": "FARGATE",
                    "maxvCpus": max_vcpus,
                    "subnets": subnets,
                    "securityGroupIds": [sg_id],
                },
                tags=_MANAGED_TAGS,
            )
            break
        except ClientError as exc:
            last_err = exc
            time.sleep(5)
    if resp is None:
        raise AssertionError(f"could not create compute environment after role propagation wait: {last_err}")
    ctx.on_cleanup(lambda: _teardown_ce(bat, name))
    return name, resp["computeEnvironmentArn"]


def _teardown_ce(bat, name):
    _swallow(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
    _wait_ce_status(bat, name, {"VALID", "INVALID"}, timeout_s=90, interval_s=3)
    # DeleteComputeEnvironment is refused while a job queue (still DELETING) references the
    # environment, and the environment's Fargate ENIs stay until it is gone, so retry and wait.
    deadline = time.monotonic() + 900.0
    while True:
        try:
            bat.delete_compute_environment(computeEnvironment=name)
            break
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(15)
    _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is None or ce.get("status") == "DELETED",
        timeout_s=max(60.0, deadline - time.monotonic()), interval_s=15,
        description=f"compute environment {name} deleted",
    )


def _create_job_queue(ctx, bat, ce_arn, priority=10):
    name = ctx.unique_name("sim2real-behav-jq-")
    resp = bat.create_job_queue(
        jobQueueName=name,
        state="ENABLED",
        priority=priority,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _teardown_jq(bat, name))
    return name, resp["jobQueueArn"]


def _teardown_jq(bat, name):
    try:
        bat.update_job_queue(jobQueue=name, state="DISABLED")
        _wait_jq_status(bat, name, {"VALID", "INVALID"}, timeout_s=60)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    bat.delete_job_queue(jobQueue=name)
    _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is None or jq.get("status") == "DELETED",
        timeout_s=600, interval_s=10,
        description=f"job queue {name} deleted",
    )


def _register_job_definition(ctx, bat, exec_role_arn):
    name = ctx.unique_name("sim2real-behav-jd-")
    resp = bat.register_job_definition(
        jobDefinitionName=name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties={
            "image": "public.ecr.aws/docker/library/busybox:1.36",
            "command": ["echo", "hello-sim2real"],
            "executionRoleArn": exec_role_arn,
            "resourceRequirements": [
                {"type": "VCPU", "value": "0.25"},
                {"type": "MEMORY", "value": "512"},
            ],
            "networkConfiguration": {"assignPublicIp": "ENABLED"},
        },
    )
    revision = resp["revision"]
    ctx.on_cleanup(lambda: _swallow(lambda: bat.deregister_job_definition(jobDefinition=f"{name}:{revision}")))
    return name, revision


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
