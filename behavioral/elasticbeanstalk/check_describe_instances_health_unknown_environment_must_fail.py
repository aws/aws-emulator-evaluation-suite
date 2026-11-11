"""describe-instances-health-unknown-environment-must-fail."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-instances-health-unknown-environment-must-fail"
GROUP = "overly-permissive"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeInstancesHealth rejects an environment id that resolves to no environment with
    InvalidParameterValue, not an empty InstanceHealthList, while a real environment id
    succeeds: a targeted rejection of the unresolvable id, not a blanket failure."""
    eb = ctx.client("elasticbeanstalk")

    app_name = ctx.unique_name("sim2real-ebih-app-")
    env_name = ctx.unique_name("sim2real-ebih-env-")[:40]

    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda: _delete_application(eb, app_name))

    stack = _pick_solution_stack(eb)
    created = eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        OptionSettings=[
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
        ],
    )
    ctx.on_cleanup(lambda: _terminate_and_wait(eb, env_name))
    real_env_id = created["EnvironmentId"]

    # Positive control: a real environment id is accepted by the same operation the negative
    # below targets -- without this, "rejects a bogus id" is indistinguishable from "rejects
    # every id".
    real_health = _wait_health_queryable(eb, real_env_id)
    assert real_health is not None, (
        f"real environment {real_env_id} never became queryable for DescribeInstancesHealth"
    )

    # Well-formed (e-<alnum>) so it passes input validation and is refused as unknown.
    bogus_env_id = "e-" + ctx.unique_name("sim2real-eb-ghost-")[-10:]

    code, message = _error(lambda: eb.describe_instances_health(EnvironmentId=bogus_env_id))
    # Empirically (real AWS): an EnvironmentId that resolves to no environment at all is
    # reported as InvalidParameterValue, not the enhanced-health-disabled InvalidRequestException.
    assert code == "InvalidParameterValue", f"unexpected error code: {code} ({message!r})"
    expected = f"No Environment found for EnvironmentId = '{bogus_env_id}'."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent / sanity: the bogus id really doesn't correspond to any environment.
    envs = eb.describe_environments(EnvironmentIds=[bogus_env_id], IncludeDeleted=False)[
        "Environments"
    ]
    assert envs == [], f"bogus id unexpectedly resolved to a real environment: {envs}"

    # Distinct rejection, not a blanket-failure artifact: calling with *neither* EnvironmentId
    # nor EnvironmentName is a different invalid shape (empirically MissingParameter on real
    # AWS) -- proves the InvalidParameterValue above is specifically about the unresolvable id,
    # not the operation always erroring regardless of input.
    code2, message2 = _error(lambda: eb.describe_instances_health())
    assert code2 == "MissingParameter", (
        f"unexpected error code for no-identifier call: {code2} ({message2!r})"
    )
    expected2 = "You must specify either EnvironmentName or EnvironmentId."
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"


# ===== helpers =====
def _error(fn):
    """Return (code, message) of the ClientError ``fn`` raises; a success is an AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks().get("SolutionStacks", [])
    for s in stacks:
        if "Windows" not in s:
            return s
    return stacks[0]


def _wait_health_queryable(eb, env_id, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = eb.describe_instances_health(EnvironmentId=env_id, AttributeNames=["HealthStatus"])
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
