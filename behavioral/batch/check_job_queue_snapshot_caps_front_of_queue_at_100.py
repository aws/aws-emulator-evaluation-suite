"""job-queue-snapshot-caps-front-of-queue-at-100."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "job-queue-snapshot-caps-front-of-queue-at-100"
GROUP = "data-plane"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """With 105 RUNNABLE jobs on the queue, GetJobQueueSnapshot's frontOfQueue holds exactly 100
    unique job ARNs, all from that backlog: the snapshot caps at the first 100 RUNNABLE jobs and
    has no pagination."""
    batch = ctx.client("batch")
    subnet_id, sg_id = _default_subnet_and_sg(ctx)
    role_arn = _create_fargate_execution_role(ctx)

    ce_name = ctx.unique_name("sim2real-batch-ce2-")
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

    jq_name = ctx.unique_name("sim2real-batch-jq2-")
    batch.create_job_queue(
        jobQueueName=jq_name,
        priority=1,
        state="ENABLED",
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
        tags=dict(_MANAGED_TAGS),
    )
    ctx.on_cleanup(lambda: _teardown_job_queue(ctx, jq_name))
    _wait_for_queue_valid(ctx, jq_name)

    jd_name = ctx.unique_name("sim2real-batch-jd2-")
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
        tags=dict(_MANAGED_TAGS),
    )
    jd_arn = job_def["jobDefinitionArn"]
    ctx.on_cleanup(lambda: batch.deregister_job_definition(jobDefinition=jd_arn))

    total = 105
    submitted: list[tuple[str, str]] = []  # (jobId, jobArn) in submission order
    for i in range(total):
        resp = batch.submit_job(
            jobName=ctx.unique_name(f"sim2real-batch-bj{i}-"),
            jobQueue=jq_name,
            jobDefinition=jd_arn,
        )
        submitted.append((resp["jobId"], resp["jobArn"]))
    all_ids = [jid for jid, _ in submitted]
    ctx.on_cleanup(lambda: _terminate_all(ctx, all_ids))

    def _all_statuses() -> dict[str, str]:
        statuses: dict[str, str] = {}
        for start in range(0, len(all_ids), 100):
            chunk = all_ids[start : start + 100]
            for j in batch.describe_jobs(jobs=chunk)["jobs"]:
                statuses[j["jobId"]] = j["status"]
        return statuses

    statuses = _poll_until(
        _all_statuses, lambda s: all(s.get(jid) == "RUNNABLE" for jid in all_ids), timeout_s=180.0, interval_s=5.0
    )
    assert all(statuses[jid] == "RUNNABLE" for jid in all_ids), statuses
    expected_arns = {arn for _, arn in submitted}

    def snapshot_probe() -> dict[str, Any]:
        return batch.get_job_queue_snapshot(jobQueue=jq_name)

    snap = _poll_until(
        snapshot_probe,
        lambda s: len(s["frontOfQueue"]["jobs"]) == 100,
        timeout_s=120.0,
        interval_s=5.0,
    )
    front = snap["frontOfQueue"]["jobs"]
    front_arns = [j["jobArn"] for j in front]

    assert len(front_arns) == 100, f"expected the documented 100-job cap, got {len(front_arns)}"
    assert len(set(front_arns)) == 100, "duplicate job ARNs present in the snapshot"
    assert set(front_arns).issubset(expected_arns), (
        "frontOfQueue contains a job ARN that was never submitted to this backlog"
    )


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _default_subnet_and_sg(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "the network VPC is not visible to DescribeVpcs; a VPC with subnets and a security "
            "group is required to build a Fargate compute environment for this check"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("the network has no subnets available for Fargate networking")
    subnet_id = subnets[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("the network VPC has no default security group")
    return subnet_id, sgs[0]["GroupId"]


def _create_fargate_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-fgexec2-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=_tags_kv()
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


def _delete_compute_environment_and_wait(batch, name, timeout_s=300.0, interval_s=5.0):
    """DeleteComputeEnvironment, then wait until it is gone. The delete is asynchronous and needs
    the service role until it completes, so returning early lets a later cleanup delete the role
    and strand the environment."""
    from botocore.exceptions import ClientError

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
