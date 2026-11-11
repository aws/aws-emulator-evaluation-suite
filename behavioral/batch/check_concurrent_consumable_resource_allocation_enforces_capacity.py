"""concurrent-consumable-resource-allocation-enforces-capacity."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-consumable-resource-allocation-enforces-capacity"
GROUP = "concurrency"
SERVICES = ["batch"]

_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two jobs concurrently claiming more units of a fixed-quantity consumable resource than
    available result in exactly one admitted at a time; the resource's in-use quantity never
    exceeds its total, and the pending job is admitted only once the winner releases its unit."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    batch = ctx.client("batch")

    subnet_id, sg_id = _default_subnet_and_sg(ctx)
    exec_role_arn = _create_execution_role(ctx)
    # Generous CE capacity: the constraint under test is the consumable resource, not vCPU/memory.
    ce_arn, _ = _create_fargate_compute_environment(
        ctx, ctx.unique_name("sim2real-batch-ce-"), subnet_id, sg_id, teardown_deadline, max_vcpus=4
    )
    jq_arn = _create_job_queue(
        ctx, ctx.unique_name("sim2real-batch-jq-"), [{"order": 1, "computeEnvironment": ce_arn}], teardown_deadline
    )

    # A NON_REPLENISHABLE resource never returns its consumed quantity, so the pending job could
    # never be admitted; the release leg needs REPLENISHABLE.
    cr_name = ctx.unique_name("sim2real-batch-cr-")
    cr_arn = batch.create_consumable_resource(
        consumableResourceName=cr_name,
        resourceType="REPLENISHABLE",
        totalQuantity=1,
        tags={"sim2real:managed": "true"},
    )["consumableResourceArn"]
    ctx.on_cleanup(lambda: batch.delete_consumable_resource(consumableResource=cr_arn))

    jobdef_arn = _register_job_definition(
        ctx,
        ctx.unique_name("sim2real-batch-jd-"),
        exec_role_arn,
        command=["sleep", "40"],
        consumable_resource_properties={"consumableResourceList": [{"consumableResource": cr_arn, "quantity": 1}]},
    )

    def _submit(tag: str) -> str:
        job_id = batch.submit_job(
            jobName=ctx.unique_name(f"sim2real-batch-job-{tag}-"), jobQueue=jq_arn, jobDefinition=jobdef_arn
        )["jobId"]

        def _terminate():
            batch.terminate_job(jobId=job_id, reason="sim2real-cleanup")

        ctx.on_cleanup(_terminate)
        return job_id

    _warm_up_execution_role(ctx, jq_arn, exec_role_arn)

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_submit, "a")
        fut_b = pool.submit(_submit, "b")
        job_a, job_b = fut_a.result(), fut_b.result()

    # Sample the resource's accounting while both jobs contend for the single unit; it must
    # never show more than the total (1) in use, and must always be internally consistent.
    observed_in_use = []

    def _sample():
        # availableQuantity and inUseQuantity are tracked independently and can be briefly out
        # of sync while a job is mid-admission; poll a short bounded window for the two figures
        # to reconcile before treating the reading as authoritative.
        detail = _poll_until(
            lambda: batch.describe_consumable_resource(consumableResource=cr_arn),
            lambda d: d["availableQuantity"] == d["totalQuantity"] - d["inUseQuantity"],
            timeout_s=15,
            interval_s=1,
        )
        observed_in_use.append(detail["inUseQuantity"])
        return detail

    def _one_job_running():
        return _describe_job(ctx, job_a)["status"] in ("STARTING", "RUNNING") or _describe_job(ctx, job_b)["status"] in ("STARTING", "RUNNING")

    _poll_until(_one_job_running, lambda ok: ok, timeout_s=240, interval_s=5)
    for _ in range(6):
        detail = _sample()
        assert detail["inUseQuantity"] <= 1, f"consumable resource over-allocated: {detail}"
        assert detail["availableQuantity"] == detail["totalQuantity"] - detail["inUseQuantity"], (
            f"availableQuantity/inUseQuantity must reconcile against totalQuantity: {detail}"
        )
        time.sleep(2)
    assert max(observed_in_use) == 1, "expected the winning job to actually hold the single unit"

    status_a = _describe_job(ctx, job_a)["status"]
    status_b = _describe_job(ctx, job_b)["status"]
    running_statuses = {"STARTING", "RUNNING", "SUCCEEDED"}
    pending_statuses = {"SUBMITTED", "PENDING", "RUNNABLE"}
    assert (status_a in running_statuses) != (status_b in running_statuses), (
        f"exactly one job should have progressed past RUNNABLE, got a={status_a} b={status_b}"
    )
    assert (status_a in pending_statuses) or (status_b in pending_statuses), (
        f"the loser must remain pending while the resource is held, got a={status_a} b={status_b}"
    )
    winner_job, loser_job = (job_a, job_b) if status_a in running_statuses else (job_b, job_a)

    # Both jobs must eventually complete: the loser is admitted once the winner releases its unit.
    final_a = _poll_until(lambda: _describe_job(ctx, job_a)["status"], lambda s: s in ("SUCCEEDED", "FAILED"), timeout_s=300, interval_s=5)
    final_b = _poll_until(lambda: _describe_job(ctx, job_b)["status"], lambda s: s in ("SUCCEEDED", "FAILED"), timeout_s=300, interval_s=5)
    assert final_a == "SUCCEEDED" and final_b == "SUCCEEDED", (
        f"both jobs must reach SUCCEEDED, got job_a={final_a!r} job_b={final_b!r}"
    )
    final_detail = batch.describe_consumable_resource(consumableResource=cr_arn)
    assert final_detail["inUseQuantity"] == 0, "resource must be fully released once both jobs finish"

    # startedAt/stoppedAt order the two jobs, which a single status snapshot cannot.
    winner_detail, loser_detail = _describe_job(ctx, winner_job), _describe_job(ctx, loser_job)
    assert isinstance(winner_detail.get("stoppedAt"), int) and isinstance(loser_detail.get("startedAt"), int), (
        f"a SUCCEEDED job must report startedAt/stoppedAt: winner={winner_detail!r} loser={loser_detail!r}"
    )
    assert loser_detail["startedAt"] >= winner_detail["stoppedAt"], (
        "the loser must not start before the winner released the unit: "
        f"winner stoppedAt={winner_detail['stoppedAt']} loser startedAt={loser_detail['startedAt']}"
    )


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
    # ECS reports a just-created execution role as unassumable until IAM propagates it; run()
    # places a warm-up job and resubmits it on that failure.
    _poll_until(
        lambda: [p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]],
        lambda arns: _EXEC_POLICY_ARN in arns,
        timeout_s=60,
        interval_s=2,
    )
    return role_arn


def _warm_up_execution_role(ctx, jq_arn, exec_role_arn):
    """Run one job without the consumable resource until it SUCCEEDS, resubmitting it while it
    FAILS with a statusReason naming the execution role (IAM propagation); any other FAILED raises."""
    batch = ctx.client("batch")
    jobdef_arn = _register_job_definition(ctx, ctx.unique_name("sim2real-batch-jd-"), exec_role_arn)
    deadline = time.monotonic() + min(300.0, ctx.time_left())
    while True:
        job_id = batch.submit_job(
            jobName=ctx.unique_name("sim2real-batch-job-warm-"), jobQueue=jq_arn, jobDefinition=jobdef_arn
        )["jobId"]
        ctx.on_cleanup(lambda job_id=job_id: batch.terminate_job(jobId=job_id, reason="sim2real-cleanup"))
        job = _poll_until(
            lambda: _describe_job(ctx, job_id),
            lambda j: j["status"] in ("SUCCEEDED", "FAILED"),
            timeout_s=max(0.0, deadline - time.monotonic()),
            interval_s=2,
        )
        if job["status"] == "SUCCEEDED":
            return
        reason = job.get("statusReason") or ""
        if exec_role_arn not in reason or time.monotonic() >= deadline:
            raise AssertionError(f"warm-up job {job_id} FAILED: {reason!r}")
        time.sleep(2)


def _create_fargate_compute_environment(ctx, name, subnet_id, sg_id, teardown_deadline, max_vcpus=4):
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
        tags={"sim2real:managed": "true"},
    )["computeEnvironmentArn"]
    ctx.on_cleanup(lambda: _delete_compute_environment(ctx, ce_arn, teardown_deadline))
    detail = _poll_until(
        lambda: batch.describe_compute_environments(computeEnvironments=[ce_arn])["computeEnvironments"][0],
        lambda d: d["status"] in ("VALID", "INVALID"),
        timeout_s=120,
    )
    assert detail["status"] == "VALID", f"compute environment failed to become VALID: {detail.get('statusReason')}"
    return ce_arn, detail.get("ecsClusterArn")


def _delete_compute_environment(ctx, ce_arn, teardown_deadline):
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
    _delete_retrying(lambda: batch.delete_compute_environment(computeEnvironment=ce_arn), teardown_deadline)


# The batch suite's cleanup budget (900 s), one deadline shared by every teardown of a run.
_TEARDOWN_RETRY_S = 900.0


def _delete_retrying(call, teardown_deadline):
    """Run a Batch delete; retry its ClientException refusals every 2 s to the shared deadline.

    A queue still draining or a compute environment still referenced refuses the delete with
    ClientException; an already-deleted resource returns; every other error raises.
    """
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)
    while True:
        try:
            call()
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                return
            if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_job_queue(ctx, name, ce_order, teardown_deadline, priority=1):
    batch = ctx.client("batch")
    jq_arn = batch.create_job_queue(
        jobQueueName=name, state="ENABLED", priority=priority, computeEnvironmentOrder=ce_order,
        tags={"sim2real:managed": "true"},
    )["jobQueueArn"]
    ctx.on_cleanup(lambda: _delete_job_queue(ctx, jq_arn, teardown_deadline))
    detail = _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[jq_arn])["jobQueues"][0],
        lambda d: d["status"] in ("VALID", "INVALID"),
        timeout_s=120,
    )
    assert detail["status"] == "VALID", f"job queue failed to become VALID: {detail.get('statusReason')}"
    return jq_arn


def _delete_job_queue(ctx, jq_arn, teardown_deadline):
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
    _delete_retrying(lambda: batch.delete_job_queue(jobQueue=jq_arn), teardown_deadline)


def _register_job_definition(ctx, name, exec_role_arn, vcpu="0.25", memory="512", command=None,
                              consumable_resource_properties=None):
    batch = ctx.client("batch")
    kwargs = dict(
        jobDefinitionName=name,
        type="container",
        platformCapabilities=["FARGATE"],
        tags={"sim2real:managed": "true"},
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
    arn = batch.register_job_definition(**kwargs)["jobDefinitionArn"]
    ctx.on_cleanup(lambda: batch.deregister_job_definition(jobDefinition=arn))
    return arn


def _describe_job(ctx, job_id):
    batch = ctx.client("batch")
    return batch.describe_jobs(jobs=[job_id])["jobs"][0]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
