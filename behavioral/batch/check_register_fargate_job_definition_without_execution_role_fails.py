"""register-fargate-job-definition-without-execution-role-fails."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "register-fargate-job-definition-without-execution-role-fails"
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
    _poll_until(
        lambda: any(
            p["PolicyArn"] == _ECS_TASK_EXECUTION_POLICY
            for p in iam.list_attached_role_policies(RoleName=_FARGATE_EXEC_ROLE_NAME).get(
                "AttachedPolicies", []
            )
        ),
        lambda attached: attached,
        timeout_s=60,
        interval_s=2.0,
        description=f"{_FARGATE_EXEC_ROLE_NAME} has {_ECS_TASK_EXECUTION_POLICY} attached",
    )
    return arn


def _deregister_jd(bat, name, revision):
    _swallow(lambda: bat.deregister_job_definition(jobDefinition=f"{name}:{revision}"))


def _register_with_role(bat, *, timeout_s=90.0, interval_s=5.0, **kwargs):
    """register_job_definition, retrying while IAM's cross-service trust grant to
    ecs-tasks.amazonaws.com has not yet propagated to Batch.

    IAM exposes no condition reporting that a role has become assumable by another service, so
    this is observable only as a transient ClientException immediately after the role's policy
    already reads back attached -- never as a queryable pre-check. A non-transient ClientException
    (a genuinely malformed request) re-raises immediately rather than burning the deadline.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return bat.register_job_definition(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "ClientException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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
    """A FARGATE job definition without executionRoleArn is refused and mints no revision.

    Fargate needs the role to pull images and write logs; the same definition with it registers.
    """
    bat = ctx.client("batch")
    exec_role = _fargate_execution_role_arn(ctx)
    name = ctx.unique_name("sim2real-behav-jd-noexec-")
    props = {
        "image": "public.ecr.aws/docker/library/busybox:1.36",
        "command": ["/bin/sh", "-c", "exit 0"],
        "resourceRequirements": [
            {"type": "VCPU", "value": "0.25"},
            {"type": "MEMORY", "value": "512"},
        ],
        "networkConfiguration": {"assignPublicIp": "ENABLED"},
    }

    ok = _register_with_role(
        bat,
        jobDefinitionName=name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties=dict(props, executionRoleArn=exec_role),
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _deregister_jd(bat, name, ok["revision"]))
    assert ok["revision"] == 1, f"first registration of a fresh name must be revision 1, got {ok['revision']}"

    code, message, request_id = _client_error(lambda: bat.register_job_definition(
        jobDefinitionName=name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties=dict(props),
        tags=_MANAGED_TAGS,
    ))
    assert code == "ClientException", (
        f"a FARGATE job definition without executionRoleArn must be rejected with "
        f"ClientException, got {code!r}"
    )
    expected = (
        "Error executing request, Exception : executionRoleArn is required for Fargate jobs., "
        f"RequestId: {request_id}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    revs = [d["revision"] for d in _describe_jd_revisions(bat, name)]
    assert revs == [1], f"the rejected registration must not mint a revision; ACTIVE revisions are {revs}"
    assert bat.describe_job_definitions(jobDefinitions=[f"{name}:2"]).get("jobDefinitions") == [], (
        f"{name}:2 must not exist after the rejection"
    )

    again = bat.register_job_definition(
        jobDefinitionName=name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties=dict(props, executionRoleArn=exec_role),
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _deregister_jd(bat, name, again["revision"]))
    assert again["revision"] == 2, (
        f"the rejection must not consume a revision number: expected 2, got {again['revision']}"
    )
    active = _describe_jd_revisions(bat, name)
    assert [d["revision"] for d in active] == [1, 2], (
        f"expected revisions [1, 2] after the control registration, got {[d['revision'] for d in active]}"
    )
    assert all(d["status"] == "ACTIVE" for d in active), (
        f"both revisions must be ACTIVE, got {[(d['revision'], d['status']) for d in active]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
