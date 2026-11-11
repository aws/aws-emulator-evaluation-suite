"""register-fargate-job-definition-illegal-vcpu-memory-pair-fails."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "register-fargate-job-definition-illegal-vcpu-memory-pair-fails"
GROUP = 'overly-permissive'
SERVICES = ['batch']

# ===== helpers =====

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_FARGATE_EXEC_ROLE_NAME = "sim2real-behav-batch-exec-role"
_ECS_TASK_EXECUTION_POLICY = (
    "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
)
_ECS_TASKS_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ecs-tasks.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
# Bounded deadlines, each with its reason.
_CE_VALID_S = 300      # a MANAGED/FARGATE CE provisions a backing ECS cluster
_JQ_VALID_S = 300      # queue VALID follows CE association
_TEARDOWN_S = 300      # DISABLED -> VALID -> deleted -> gone, per resource
_JOB_TERMINAL_S = 900  # Fargate cold start + public.ecr.aws image pull + run


def _swallow(fn):
    """Run fn(); only a resource that is already gone is ignored, every other failure raises."""
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


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_role(ctx, role_name, policy_arn):
    """Detach the managed policy then delete an IAM role; a failure raises."""
    iam = ctx.client("iam")
    _swallow(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _swallow(lambda: iam.delete_role(RoleName=role_name))


def _fargate_execution_role_arn(ctx):
    """Create-or-reuse the ECS task execution role for Fargate Batch jobs; returns its ARN.

    Deletion cleanup is registered only when THIS check created the role, so a shared
    pre-existing role is never reaped out from under a concurrent check.
    """
    iam = ctx.client("iam")
    try:
        return iam.get_role(RoleName=_FARGATE_EXEC_ROLE_NAME)["Role"]["Arn"]
    except Exception:
        pass
    try:
        resp = iam.create_role(
            RoleName=_FARGATE_EXEC_ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(_ECS_TASKS_TRUST_POLICY),
            Description="SimParity behavioral suite: Batch Fargate task execution role",
            Tags=_tags_kv(),
        )
        arn = resp["Role"]["Arn"]
    except Exception as exc:
        try:
            return iam.get_role(RoleName=_FARGATE_EXEC_ROLE_NAME)["Role"]["Arn"]
        except Exception:
            raise AssertionError(
                f"cannot create/resolve the Fargate task execution role: {exc}"
            ) from exc
    _swallow(lambda: iam.attach_role_policy(RoleName=_FARGATE_EXEC_ROLE_NAME, PolicyArn=_ECS_TASK_EXECUTION_POLICY))
    ctx.on_cleanup(lambda: _delete_role(ctx, _FARGATE_EXEC_ROLE_NAME, _ECS_TASK_EXECUTION_POLICY))
    return arn


_ROLE_PROPAGATION_S = 60  # ECS/Batch can reject a role IAM already returns as created


def _register_job_definition_awaiting_role(bat, **kwargs):
    """RegisterJobDefinition, retrying only the specific role-not-yet-usable failure.

    IAM is eventually consistent: Batch/ECS can fail to resolve or assume a role created
    moments ago even though `iam.get_role`/`create_role` already returned it. Retry that one
    failure, bounded -- never a blind sleep.
    """
    deadline = time.monotonic() + _ROLE_PROPAGATION_S
    while True:
        try:
            return bat.register_job_definition(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            retriable = err.get("Code") == "ClientException" and "role" in err.get("Message", "").lower()
            if retriable and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


def _deregister_jd(bat, name, revision):
    _swallow(lambda: bat.deregister_job_definition(jobDefinition=f"{name}:{revision}"))


def _client_error(fn):
    """Call fn(); return (Error.Code, Error.Message, RequestId) of the ClientError it raises. An
    unexpected SUCCESS raises, so accepting input AWS refuses is never a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message"), exc.response.get("ResponseMetadata", {}).get("RequestId")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _describe_jd_revisions(bat, name, status=None):
    """All revisions of one job-definition NAME, ascending. status=None means ACTIVE-only."""
    kwargs = {"jobDefinitionName": name}
    if status:
        kwargs["status"] = status
    out, token = [], None
    while True:
        if token:
            kwargs["nextToken"] = token
        resp = bat.describe_job_definitions(**kwargs)
        out.extend(resp.get("jobDefinitions", []))
        token = resp.get("nextToken")
        if not token:
            break
    return sorted(out, key=lambda d: d["revision"])

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Fargate accepts only fixed VCPU/MEMORY pairings: 0.25 vCPU with 4096 MiB is refused.

    No revision is minted, and legal 0.25/512 and 0.5/1024 pairings register and echo back.
    """
    bat = ctx.client("batch")
    exec_role = _fargate_execution_role_arn(ctx)
    name = ctx.unique_name("sim2real-behav-jd-badsize-")

    def props(vcpu, memory):
        return {
            "image": "public.ecr.aws/docker/library/busybox:1.36",
            "command": ["/bin/sh", "-c", "exit 0"],
            "executionRoleArn": exec_role,
            "resourceRequirements": [
                {"type": "VCPU", "value": vcpu},
                {"type": "MEMORY", "value": memory},
            ],
            "networkConfiguration": {"assignPublicIp": "ENABLED"},
        }

    ok = _register_job_definition_awaiting_role(
        bat,
        jobDefinitionName=name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties=props("0.25", "512"),
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _deregister_jd(bat, name, ok["revision"]))
    assert ok["revision"] == 1, f"expected revision 1, got {ok['revision']}"
    reqs = {r["type"]: r["value"] for r in
            (_describe_jd_revisions(bat, name)[0]["containerProperties"]["resourceRequirements"])}
    assert reqs == {"VCPU": "0.25", "MEMORY": "512"}, (
        f"the registered resourceRequirements must be echoed back verbatim, got {reqs}"
    )

    # 0.25 vCPU offers only 512/1024/2048 MiB.
    code, message, request_id = _client_error(lambda: bat.register_job_definition(
        jobDefinitionName=name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties=props("0.25", "4096"),
        tags=_MANAGED_TAGS,
    ))
    assert code == "ClientException", (
        f"0.25 vCPU with 4096 MiB is not a valid Fargate task size and must be rejected with "
        f"ClientException, got {code!r}"
    )
    expected = (
        "Error executing request, Exception : Fargate resource requirements (0.25 vCPU, 4096 MiB) "
        f"not valid., RequestId: {request_id}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    revs = [d["revision"] for d in _describe_jd_revisions(bat, name)]
    assert revs == [1], f"the rejected registration must not mint a revision; got {revs}"

    again = bat.register_job_definition(
        jobDefinitionName=name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties=props("0.5", "1024"),
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _deregister_jd(bat, name, again["revision"]))
    assert again["revision"] == 2, f"expected the control registration to be revision 2, got {again['revision']}"
    rev2 = [d for d in _describe_jd_revisions(bat, name) if d["revision"] == 2][0]
    reqs2 = {r["type"]: r["value"] for r in rev2["containerProperties"]["resourceRequirements"]}
    assert reqs2 == {"VCPU": "0.5", "MEMORY": "1024"}, (
        f"the control revision must echo its own resourceRequirements, got {reqs2}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
