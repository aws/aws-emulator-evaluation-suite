"""server-side-job-placement-honors-compute-environment-order."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "server-side-job-placement-honors-compute-environment-order"
GROUP = "server-side"
SERVICES = ["batch"]

_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The managed scheduler places a runnable job onto the compute environment with the lowest
    `order` value in the job queue's computeEnvironmentOrder list, ahead of an equally-capable
    compute environment listed at a higher order value."""
    batch = ctx.client("batch")

    subnet_id, sg_id = _default_subnet_and_sg(ctx)
    exec_role_arn = _create_execution_role(ctx)

    # Two equally-capable Fargate compute environments; CE-A is order=1 (preferred), CE-B order=2.
    ce_a_arn, ce_a_cluster = _create_fargate_compute_environment(ctx, ctx.unique_name("sim2real-batch-cea-"), subnet_id, sg_id, max_vcpus=4)
    ce_b_arn, ce_b_cluster = _create_fargate_compute_environment(ctx, ctx.unique_name("sim2real-batch-ceb-"), subnet_id, sg_id, max_vcpus=4)
    assert ce_a_cluster and ce_b_cluster and ce_a_cluster != ce_b_cluster, (
        f"expected two distinct ECS clusters backing CE-A and CE-B, got {ce_a_cluster!r} and {ce_b_cluster!r}"
    )

    jq_arn = _create_job_queue(
        ctx,
        ctx.unique_name("sim2real-batch-jq-"),
        [{"order": 1, "computeEnvironment": ce_a_arn}, {"order": 2, "computeEnvironment": ce_b_arn}],
    )

    jobdef_arn = _register_job_definition(ctx, ctx.unique_name("sim2real-batch-jd-"), exec_role_arn, command=["echo", "hello"])
    job_id = batch.submit_job(jobName=ctx.unique_name("sim2real-batch-job-"), jobQueue=jq_arn, jobDefinition=jobdef_arn)["jobId"]

    # container.taskArn is populated once the attempt reaches STARTING; its ARN embeds the ECS
    # cluster name (arn:aws:ecs:region:account:task/<cluster-name>/<task-id>), which tells us
    # unambiguously which compute environment's underlying cluster ran the job.
    detail = _poll_until(
        lambda: _describe_job(ctx, job_id),
        lambda d: d.get("container", {}).get("taskArn"),
        timeout_s=240,
        interval_s=5,
    )
    task_arn = detail["container"]["taskArn"]
    task_cluster_name = task_arn.split("/")[-2]
    ce_a_cluster_name = ce_a_cluster.split("/")[-1]
    ce_b_cluster_name = ce_b_cluster.split("/")[-1]

    assert task_cluster_name == ce_a_cluster_name, (
        f"job was placed on cluster {task_cluster_name!r}, expected the order=1 CE's cluster {ce_a_cluster_name!r}"
    )
    assert task_cluster_name != ce_b_cluster_name, (
        f"job was placed on the order=2 CE's cluster {ce_b_cluster_name!r}, which the order=1 CE should have preempted"
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
    # IAM role propagation is eventually consistent; poll a cheap read back before handing the
    # ARN to ECS. The CE/queue/job provisioning that follows adds further real elapsed time
    # before ECS ever assumes this role.
    _poll_until(
        lambda: iam.get_role(RoleName=role_name)["Role"]["Arn"],
        lambda arn: arn == role_arn,
        timeout_s=30.0,
        interval_s=2.0,
    )
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
        tags=_MANAGED_TAGS,
    )["computeEnvironmentArn"]
    ctx.on_cleanup(lambda: _delete_compute_environment(ctx, ce_arn))
    detail = _poll_until(
        lambda: batch.describe_compute_environments(computeEnvironments=[ce_arn])["computeEnvironments"][0],
        lambda d: d["status"] in ("VALID", "INVALID"),
        timeout_s=120,
    )
    assert detail["status"] == "VALID", f"compute environment failed to become VALID: {detail.get('statusReason')}"
    return ce_arn, detail.get("ecsClusterArn")


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
    _delete_retrying(lambda: batch.delete_compute_environment(computeEnvironment=ce_arn))


def _delete_retrying(delete, budget_s=100.0):
    """Run a Batch delete; a resource that does not exist is done. Batch refuses a delete with
    ClientException while a dependent resource is still releasing, so that is retried every 2 s
    until budget_s, then raised."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            delete()
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                return
            if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_job_queue(ctx, name, ce_order, priority=1, state="ENABLED"):
    batch = ctx.client("batch")
    jq_arn = batch.create_job_queue(
        jobQueueName=name, state=state, priority=priority, computeEnvironmentOrder=ce_order,
        tags=_MANAGED_TAGS,
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
    _delete_retrying(lambda: batch.delete_job_queue(jobQueue=jq_arn))


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
        tags=_MANAGED_TAGS,
    )
    if consumable_resource_properties:
        kwargs["consumableResourceProperties"] = consumable_resource_properties
    arn = batch.register_job_definition(**kwargs)["jobDefinitionArn"]
    ctx.on_cleanup(lambda: batch.deregister_job_definition(jobDefinition=arn))
    return arn


def _describe_job(ctx, job_id):
    batch = ctx.client("batch")
    return batch.describe_jobs(jobs=[job_id])["jobs"][0]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
