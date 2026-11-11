"""managed-compute-environment-auto-scales-server-side."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "managed-compute-environment-auto-scales-server-side"
GROUP = "server-side"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A MANAGED EC2 compute environment at desiredvCpus=0 scales up on its own for a queued job.

    With no client scaling call, desiredvCpus rises above 0 and the job reaches RUNNING/SUCCEEDED.
    """
    ctx.client("ec2")
    batch = ctx.client("batch")
    vpc_id, subnets = _default_subnets(ctx)
    sg_id = _default_sg(ctx, vpc_id)
    instance_profile_arn = _create_ec2_instance_profile(ctx)

    ce_name = ctx.unique_name("sim2real-batch-ce-")
    ctx.on_cleanup(lambda: _drain_and_delete_ce(ctx, ce_name))
    ce = _create_and_validate_managed_ce(ctx, batch, ce_name, subnets, sg_id, instance_profile_arn)
    assert ce["computeResources"]["desiredvCpus"] == 0, "baseline desiredvCpus was not 0 before any job was queued"
    ce_arn = ce["computeEnvironmentArn"]

    queue_name = ctx.unique_name("sim2real-batch-jq-")
    _create_job_queue(ctx, queue_name, [{"order": 1, "computeEnvironment": ce_arn}], priority=1)

    jd_name = ctx.unique_name("sim2real-batch-jd-")
    batch.register_job_definition(
        jobDefinitionName=jd_name,
        type="container",
        containerProperties={
            "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
            "command": ["/bin/sh", "-c", "sleep 30"],
            "resourceRequirements": [
                {"type": "VCPU", "value": "1"},
                {"type": "MEMORY", "value": "1024"},
            ],
        },
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _try_deregister(ctx, jd_name))

    job_id = batch.submit_job(jobName=ctx.unique_name("sim2real-batch-job-"), jobQueue=queue_name, jobDefinition=jd_name)[
        "jobId"
    ]
    ctx.on_cleanup(lambda: _try_terminate(ctx, job_id))

    scaled = _poll_until(
        lambda: batch.describe_compute_environments(computeEnvironments=[ce_name])["computeEnvironments"][0],
        lambda ce: ce["computeResources"]["desiredvCpus"] > 0,
        timeout_s=300,
        interval_s=8,
    )
    assert scaled["computeResources"]["desiredvCpus"] >= 1, (
        f"desiredvCpus never rose above baseline in response to the queued job: "
        f"{scaled['computeResources']['desiredvCpus']}"
    )

    running = _poll_until(
        lambda: batch.describe_jobs(jobs=[job_id])["jobs"][0],
        lambda j: j["status"] in ("RUNNING", "SUCCEEDED", "FAILED"),
        timeout_s=420,
        interval_s=8,
    )
    assert running["status"] in ("RUNNING", "SUCCEEDED"), (
        f"job never ran on the service-provisioned capacity: {running['status']}/{running.get('statusReason')}"
    )


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _default_subnets(ctx, count: int = 2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:

        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:

        raise AssertionError("shared network has no subnets")
    return vpc_id, [s["SubnetId"] for s in subnets[:count]]


def _default_sg(ctx, vpc_id: str) -> str:
    ec2 = ctx.client("ec2")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    return sgs[0]["GroupId"]


def _create_ec2_instance_profile(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-ec2role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=_tags_kv())
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
        )
    )

    profile = iam.create_instance_profile(InstanceProfileName=role_name, Tags=_tags_kv())
    ctx.on_cleanup(lambda: _delete_instance_profile(ctx, role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: _remove_role_from_profile(ctx, role_name)
    )
    return profile["InstanceProfile"]["Arn"]


def _remove_role_from_profile(ctx, name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.remove_role_from_instance_profile(InstanceProfileName=name, RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_instance_profile(ctx, name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_instance_profile(InstanceProfileName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_and_validate_managed_ce(ctx, batch, ce_name: str, subnets: list, sg_id: str, instance_profile_arn: str):
    """Create the MANAGED/EC2 compute environment and wait for it to reach VALID.

    A CE created before a fresh instance profile propagates lands INVALID naming the instance role,
    so it is deleted and recreated under the same name, bounded by an overall deadline.
    """
    deadline = time.monotonic() + 180.0
    attempt = 0
    last_reason = None
    while True:
        attempt += 1
        batch.create_compute_environment(
            computeEnvironmentName=ce_name,
            type="MANAGED",
            state="ENABLED",
            computeResources={
                "type": "EC2",
                "allocationStrategy": "BEST_FIT_PROGRESSIVE",
                "minvCpus": 0,
                "desiredvCpus": 0,
                "maxvCpus": 4,
                "instanceTypes": ["m5.large"],
                "subnets": subnets,
                "securityGroupIds": [sg_id],
                "instanceRole": instance_profile_arn,
            },
            tags=_MANAGED_TAGS,
        )
        ce = _poll_until(
            lambda: batch.describe_compute_environments(computeEnvironments=[ce_name])["computeEnvironments"][0],
            lambda ce: ce["status"] in ("VALID", "INVALID"),
            timeout_s=120,
            interval_s=5,
        )
        if ce["status"] == "VALID":
            return ce
        last_reason = ce.get("statusReason")
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"compute environment failed to validate after {attempt} attempt(s): {last_reason}"
            )
        _delete_ce_for_retry(batch, ce_name)


def _delete_ce_for_retry(batch, ce_name: str) -> None:
    """Delete a just-created, not-yet-VALID CE so the retry loop can recreate under the same
    name. Waits on `state` (the admin ENABLED/DISABLED toggle), never on `status` (VALID/INVALID)
    — an INVALID CE never becomes VALID by disabling it, so waiting on status here would hang."""
    batch.update_compute_environment(computeEnvironment=ce_name, state="DISABLED")
    _poll_until(
        lambda: batch.describe_compute_environments(computeEnvironments=[ce_name])["computeEnvironments"][0],
        lambda ce: ce["state"] == "DISABLED",
        timeout_s=60,
        interval_s=3,
    )
    _delete_compute_environment_and_wait(batch, ce_name)
    _poll_until(
        lambda: batch.describe_compute_environments(computeEnvironments=[ce_name])["computeEnvironments"],
        lambda ces: len(ces) == 0,
        timeout_s=60,
        interval_s=5,
    )


def _drain_and_delete_ce(ctx, name: str) -> None:
    batch = ctx.client("batch")
    try:
        batch.update_compute_environment(computeEnvironment=name, state="DISABLED")
        _poll_until(
            lambda: batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"][0],
            lambda ce: ce["status"] == "VALID",
            timeout_s=180,
            interval_s=6,
        )
        _delete_compute_environment_and_wait(batch, name)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


def _create_job_queue(ctx, name: str, ce_order: list, priority: int) -> str:
    batch = ctx.client("batch")
    resp = batch.create_job_queue(
        jobQueueName=name,
        state="ENABLED",
        priority=priority,
        computeEnvironmentOrder=ce_order,
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _drain_and_delete_jq(ctx, name))
    jq = _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"][0],
        lambda jq: jq["status"] in ("VALID", "INVALID"),
        timeout_s=120,
        interval_s=4,
    )
    assert jq["status"] == "VALID", f"job queue failed to validate: {jq.get('statusReason')}"
    return resp["jobQueueArn"]


def _drain_and_delete_jq(ctx, name: str) -> None:
    batch = ctx.client("batch")
    try:
        batch.update_job_queue(jobQueue=name, state="DISABLED")
        _poll_until(
            lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"][0],
            lambda jq: jq["status"] == "VALID",
            timeout_s=120,
            interval_s=4,
        )
        batch.delete_job_queue(jobQueue=name)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


def _try_terminate(ctx, job_id: str) -> None:
    batch = ctx.client("batch")
    job = batch.describe_jobs(jobs=[job_id])["jobs"][0]
    if job["status"] not in ("SUCCEEDED", "FAILED"):
        batch.terminate_job(jobId=job_id, reason="sim2real-behavioral-cleanup")
        _poll_until(
            lambda: batch.describe_jobs(jobs=[job_id])["jobs"][0],
            lambda j: j["status"] in ("SUCCEEDED", "FAILED"),
            timeout_s=120,
            interval_s=5,
        )


def _try_deregister(ctx, jd_name: str) -> None:
    batch = ctx.client("batch")
    for jd in batch.describe_job_definitions(jobDefinitionName=jd_name)["jobDefinitions"]:
        batch.deregister_job_definition(jobDefinition=f"{jd_name}:{jd['revision']}")



def _delete_compute_environment_and_wait(batch, name, timeout_s=300.0, interval_s=5.0):
    """DeleteComputeEnvironment, then wait until it is gone. The delete is asynchronous and needs
    the service role until it completes, so returning early lets a later cleanup delete the role
    and strand the environment."""
    batch.delete_compute_environment(computeEnvironment=name)
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
