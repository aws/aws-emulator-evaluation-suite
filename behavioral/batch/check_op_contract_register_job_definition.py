"""op-contract-registerJobDefinition."""
from __future__ import annotations
from botocore.exceptions import ClientError

CHECK = "op-contract-registerJobDefinition"
GROUP = "error-semantics"
SERVICES = ["batch"]

from behavioral_harness import tags

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterJobDefinition creates ACTIVE revision 1, then increments to revision 2 on
    re-registration; a Fargate job definition without executionRoleArn is rejected, while an
    otherwise-identical Fargate definition WITH the role registers cleanly."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jd-")
    container = {
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "command": ["sleep", "30"],
        "resourceRequirements": [{"type": "VCPU", "value": "1"}, {"type": "MEMORY", "value": "512"}],
    }

    r1 = batch.register_job_definition(
        jobDefinitionName=name, type="container", containerProperties=container, tags=_MANAGED_TAGS
    )
    ctx.on_cleanup(lambda: batch.deregister_job_definition(jobDefinition=r1["jobDefinitionArn"]))
    assert r1["revision"] == 1, f"first registration of a fresh name must be revision 1, got {r1['revision']}"
    assert r1["jobDefinitionArn"].endswith(f"/{name}:1"), f"unexpected ARN {r1['jobDefinitionArn']!r}"

    r2 = batch.register_job_definition(
        jobDefinitionName=name, type="container", containerProperties=container, tags=_MANAGED_TAGS
    )
    ctx.on_cleanup(lambda: batch.deregister_job_definition(jobDefinition=r2["jobDefinitionArn"]))
    assert r2["revision"] == 2, "re-registering the same name must auto-increment the revision"
    assert r2["jobDefinitionArn"].endswith(f"/{name}:2"), f"unexpected ARN {r2['jobDefinitionArn']!r}"

    active = batch.describe_job_definitions(jobDefinitionName=name, status="ACTIVE")["jobDefinitions"]
    revisions = sorted(jd["revision"] for jd in active)
    assert revisions == [1, 2], f"expected both revisions ACTIVE, got {revisions}"

    # Positive control: Fargate needs a task execution role to pull the image and write logs.
    # Prove the account/Fargate path itself is healthy before asserting the specific rejection —
    # without this, "rejects an incomplete Fargate job def" is indistinguishable from "rejects
    # every Fargate registration".
    exec_role = _fargate_execution_role_arn(ctx)
    fargate_props = {
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "resourceRequirements": [{"type": "VCPU", "value": "0.25"}, {"type": "MEMORY", "value": "512"}],
        "networkConfiguration": {"assignPublicIp": "ENABLED"},
    }
    control = _register_with_iam_propagation_retry(
        lambda: batch.register_job_definition(
            jobDefinitionName=ctx.unique_name("sim2real-batch-jd-fg-ok-"),
            type="container",
            platformCapabilities=["FARGATE"],
            containerProperties=dict(fargate_props, executionRoleArn=exec_role),
            tags=_MANAGED_TAGS,
        )
    )
    ctx.on_cleanup(lambda: batch.deregister_job_definition(jobDefinition=control["jobDefinitionArn"]))
    assert control["revision"] == 1, f"a valid Fargate registration must succeed, got {control!r}"

    # Error boundary: break exactly one thing (drop executionRoleArn) and assert the specific
    # rejection plus the absent effect via an independent read.
    bad_name = ctx.unique_name("sim2real-batch-jd-bad-")
    code, message, request_id = _error_code(
        lambda: batch.register_job_definition(
            jobDefinitionName=bad_name,
            type="container",
            platformCapabilities=["FARGATE"],
            containerProperties=fargate_props,
            tags=_MANAGED_TAGS,
        )
    )
    assert code == "ClientException", f"expected ClientException, got {code!r}"
    # Batch embeds the call's own request id in this message.
    expected = (
        "Error executing request, Exception : executionRoleArn is required for Fargate jobs., "
        f"RequestId: {request_id}"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"
    leftover = batch.describe_job_definitions(jobDefinitionName=bad_name)["jobDefinitions"]
    assert leftover == [], "the rejected Fargate job definition must not have been registered"


_ECS_TASK_EXECUTION_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
_ECS_TASKS_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role(ctx, role_name, policy_arn):
    """Detach the managed policy then delete an IAM role (best-effort)."""
    iam = ctx.client("iam")
    _swallow(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _swallow(lambda: iam.delete_role(RoleName=role_name))


def _fargate_execution_role_arn(ctx):
    """Create this run's own ECS task execution role for the Fargate positive control."""
    import json

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-batch-exec-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_ECS_TASKS_TRUST_POLICY),
        Description="SimParity behavioral suite: Batch Fargate task execution role",
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name, _ECS_TASK_EXECUTION_POLICY))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_ECS_TASK_EXECUTION_POLICY)
    return arn


def _register_with_iam_propagation_retry(fn, *, timeout_s=60, interval_s=3.0):
    """Bounded retry for the Fargate positive control while IAM catches up.

    A freshly created execution role is not always immediately assumable by Batch; real AWS
    answers ClientException for a few seconds after CreateRole. This is genuine eventual
    consistency, not a fixed wait -- retry until the deadline and raise with the last error if
    the role never becomes usable.
    """
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClientException":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"Fargate registration with a freshly created execution role never succeeded within "
        f"{timeout_s}s; last error: {last_exc}"
    )


def _error_code(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message, RequestId). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return (
            exc.response["Error"]["Code"],
            exc.response["Error"].get("Message"),
            exc.response["ResponseMetadata"].get("RequestId"),
        )
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
