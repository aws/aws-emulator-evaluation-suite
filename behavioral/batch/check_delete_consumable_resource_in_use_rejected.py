"""delete-consumable-resource-in-use-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-consumable-resource-in-use-rejected"
GROUP = "consumable-resource"
SERVICES = ["batch"]

_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch-cr"}


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteConsumableResource is rejected with ClientException while a running job still holds
    a unit of the resource (inUseQuantity > 0), and the resource is NOT removed. Positive
    control: once the job finishes and releases its unit, the same delete call succeeds."""
    batch = ctx.client("batch")

    subnet_id, sg_id = _default_subnet_and_sg(ctx)
    exec_role_arn = _create_execution_role(ctx)
    ce_arn, _ = _create_fargate_compute_environment(ctx, ctx.unique_name("sim2real-batch-ce-"), subnet_id, sg_id, max_vcpus=2)
    jq_arn = _create_job_queue(ctx, ctx.unique_name("sim2real-batch-jq-"), [{"order": 1, "computeEnvironment": ce_arn}])

    cr_name = ctx.unique_name("sim2real-batch-cr-")
    cr_arn = batch.create_consumable_resource(
        consumableResourceName=cr_name,
        resourceType="NON_REPLENISHABLE",
        totalQuantity=1,
        tags=_MANAGED_TAGS,
    )["consumableResourceArn"]
    cr_cleanup_done = {"value": False}

    def _cleanup_cr():
        if not cr_cleanup_done["value"]:
            batch.delete_consumable_resource(consumableResource=cr_arn)

    ctx.on_cleanup(_cleanup_cr)

    jobdef_arn = _register_job_definition(
        ctx,
        ctx.unique_name("sim2real-batch-jd-"),
        exec_role_arn,
        command=["sleep", "30"],
        consumable_resource_properties={"consumableResourceList": [{"consumableResource": cr_arn, "quantity": 1}]},
    )
    job_id = batch.submit_job(jobName=ctx.unique_name("sim2real-batch-job-"), jobQueue=jq_arn, jobDefinition=jobdef_arn)["jobId"]
    _poll_until(lambda: _describe_job(ctx, job_id)["status"], lambda s: s == "RUNNING", timeout_s=240, interval_s=5)
    assert batch.describe_consumable_resource(consumableResource=cr_arn)["inUseQuantity"] == 1

    code, message = _error_code(lambda: batch.delete_consumable_resource(consumableResource=cr_arn))
    assert code == "ClientException", f"expected ClientException deleting an in-use consumable resource, got {code}"
    expected = "Consumable resource cannot be deleted when in use"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The forbidden effect did not happen: the resource is still there and still in use.
    still_there = batch.describe_consumable_resource(consumableResource=cr_arn)
    assert still_there["consumableResourceArn"] == cr_arn
    assert still_there["inUseQuantity"] == 1

    # Positive control: once the job releases the unit, deletion succeeds.
    _poll_until(lambda: _describe_job(ctx, job_id)["status"], lambda s: s == "SUCCEEDED", timeout_s=120, interval_s=5)
    _poll_until(lambda: batch.describe_consumable_resource(consumableResource=cr_arn)["inUseQuantity"], lambda q: q == 0, timeout_s=60, interval_s=3)
    batch.delete_consumable_resource(consumableResource=cr_arn)
    cr_cleanup_done["value"] = True
    code_after, message_after = _error_code(lambda: batch.describe_consumable_resource(consumableResource=cr_arn))
    assert code_after == "ClientException", "consumable resource should no longer be describable after deletion"
    expected_gone = f"{cr_arn} does not exist"
    assert message_after == expected_gone, f"expected message {expected_gone!r}, got {message_after!r}"

    # A mutation on the dead id is rejected too, not just the read.
    update_code, update_message = _error_code(
        lambda: batch.update_consumable_resource(consumableResource=cr_arn, operation="ADD", quantity=1)
    )
    assert update_code == "ClientException", (
        f"expected ClientException updating a deleted consumable resource, got {update_code}"
    )
    assert update_message == expected_gone, f"expected message {expected_gone!r}, got {update_message!r}"


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused with a ClientError, but it succeeded")


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
    # No blind sleep for propagation: the compute environment and job queue below each poll to
    # VALID with their own deadline, and the role is not actually assumed until Fargate launches
    # the job's task well after that — so those polls are the bounded wait this role needs too.
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
        jobQueueName=name,
        state=state,
        priority=priority,
        computeEnvironmentOrder=ce_order,
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
    kwargs["tags"] = _MANAGED_TAGS
    arn = batch.register_job_definition(**kwargs)["jobDefinitionArn"]
    ctx.on_cleanup(lambda: batch.deregister_job_definition(jobDefinition=arn))
    return arn


def _describe_job(ctx, job_id):
    batch = ctx.client("batch")
    return batch.describe_jobs(jobs=[job_id])["jobs"][0]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
