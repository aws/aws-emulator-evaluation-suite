"""describe-instances-health-malformed-request-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-instances-health-malformed-request-rejected"
GROUP = "error-semantics"
SERVICES = ["elasticbeanstalk"]

ENUM_MESSAGE = (
    "1 validation error detected: Value '[NotARealAttribute]' at 'attributeNames' failed to "
    "satisfy constraint: Member must satisfy constraint: [Member must satisfy enum value set: "
    "[All, Color, Deployment, LaunchedAt, AvailabilityZone, Causes, RefreshedAt, HealthStatus, "
    "InstanceType, System, ApplicationMetrics]]"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeInstancesHealth rejects an AttributeNames value outside the documented enum with
    ValidationError, before resolving the environment (even a never-created one), while a valid
    attribute name against a real environment succeeds: the failure is about the input alone."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-beh-app-")
    env_name = ctx.unique_name("sim2real-env-")[:40]

    bogus_env_name = ctx.unique_name("sim2real-ebih-ghost-")[:40]
    code0, message0 = _error(
        lambda: eb.describe_instances_health(
            EnvironmentName=bogus_env_name, AttributeNames=["NotARealAttribute"]
        )
    )
    assert code0 == "ValidationError", (
        f"expected ValidationError for a malformed AttributeNames value even against an unknown "
        f"EnvironmentName (the enum is validated before environment identity), got {code0} "
        f"({message0!r})"
    )
    assert message0 == ENUM_MESSAGE, f"expected message {ENUM_MESSAGE!r}, got {message0!r}"

    tags = [{"Key": "sim2real:managed", "Value": "true"}]
    eb.create_application(ApplicationName=app_name, Tags=tags)
    ctx.on_cleanup(lambda: _delete_application(eb, app_name))

    stack = _pick_solution_stack(eb)
    eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        OptionSettings=[
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
        ],
        Tags=tags,
    )
    ctx.on_cleanup(lambda: _terminate_and_wait(eb, env_name))

    ok = _wait_health_queryable(eb, env_name)
    assert ok is not None, f"environment {env_name} never became queryable for DescribeInstancesHealth"
    assert isinstance(ok, list), f"expected an InstanceHealthList for a valid AttributeNames value, got {ok!r}"

    code, message = _error(
        lambda: eb.describe_instances_health(
            EnvironmentName=env_name, AttributeNames=["NotARealAttribute"]
        )
    )
    assert code == "ValidationError", (
        f"expected ValidationError for a malformed AttributeNames value, got {code} ({message!r})"
    )
    assert message == ENUM_MESSAGE, f"expected message {ENUM_MESSAGE!r}, got {message!r}"


# ===== helpers =====

def _error(fn):
    """Return (code, message) of the ClientError ``fn`` raises; a success is an AssertionError."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks().get("SolutionStacks", [])
    for s in stacks:
        if "Windows" not in s:
            return s
    return stacks[0]


def _wait_health_queryable(eb, env_name, timeout_s=120.0, interval_s=5.0):
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = eb.describe_instances_health(EnvironmentName=env_name, AttributeNames=["HealthStatus"])
            return resp.get("InstanceHealthList", [])
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidParameterValue":
                raise
            time.sleep(interval_s)
    return None


def _wait_env_status(eb, env_name, statuses, timeout_s=900.0, interval_s=15.0, include_deleted=False):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=include_deleted)
        envs = resp.get("Environments", [])
        last = envs[0] if envs else None
        if last is not None and last["Status"] in statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} never reached {statuses} within {timeout_s}s (last={last!r})")


def _terminate_and_wait(eb, env_name):
    from botocore.exceptions import ClientError
    try:
        eb.terminate_environment(EnvironmentName=env_name)
    except ClientError as exc:
        # InvalidParameterValue is "No Environment found": already terminated; anything else raises.
        if exc.response["Error"]["Code"] != "InvalidParameterValue":
            raise
    _wait_env_status(eb, env_name, {"Terminated"}, timeout_s=600, interval_s=2, include_deleted=True)


def _delete_application(eb, app_name):
    eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=False)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
