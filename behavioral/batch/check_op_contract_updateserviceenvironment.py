"""op-contract-updateserviceenvironment."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "op-contract-updateserviceenvironment"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateServiceEnvironment applies a new capacity limit and disables the environment
    (visible via DescribeServiceEnvironments), and rejects a nonexistent serviceEnvironment
    identifier with ClientException without touching the real environment."""
    batch = ctx.client("batch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-behav-svcenv-")
    batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "NUM_INSTANCES", "maxCapacity": 5}],
        state="ENABLED",
        tags={"env": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: batch.delete_service_environment(serviceEnvironment=name))

    env_before = _wait_for_status(ctx, name, {"VALID", "INVALID"}, timeout_s=120)
    assert env_before["status"] == "VALID", f"expected VALID, got {env_before}"
    assert env_before["state"] == "ENABLED", f"expected ENABLED, got {env_before['state']!r}"
    assert env_before["capacityLimits"][0]["maxCapacity"] == 5, (
        f"expected maxCapacity 5, got {env_before['capacityLimits']}"
    )

    # Success path: raise the capacity limit and disable the environment.
    update_resp = batch.update_service_environment(
        serviceEnvironment=name,
        capacityLimits=[{"capacityUnit": "NUM_INSTANCES", "maxCapacity": 10}],
        state="DISABLED",
    )
    assert update_resp["serviceEnvironmentName"] == name, (
        f"expected {name!r}, got {update_resp['serviceEnvironmentName']!r}"
    )
    assert update_resp["serviceEnvironmentArn"] == env_before["serviceEnvironmentArn"], (
        f"expected {env_before['serviceEnvironmentArn']!r}, got {update_resp['serviceEnvironmentArn']!r}"
    )

    env_after = _wait_for_status(ctx, name, {"VALID", "INVALID"}, timeout_s=120)
    assert env_after["status"] == "VALID", f"expected VALID, got {env_after}"
    assert env_after["state"] == "DISABLED", f"expected DISABLED, got {env_after['state']!r}"
    assert env_after["capacityLimits"][0]["maxCapacity"] == 10, (
        f"expected maxCapacity 10, got {env_after['capacityLimits']}"
    )

    # Error boundary: updating a serviceEnvironment identifier that was never created.
    bogus_name = ctx.unique_name("nonexistent-svcenv-")
    code, message = _client_error(
        lambda: batch.update_service_environment(serviceEnvironment=bogus_name, state="ENABLED")
    )
    assert code == "ClientException", f"expected ClientException, got {code}"
    bogus_arn = f"arn:aws:batch:{ctx.region}:{account_id}:service-environment/{bogus_name}"
    expected_message = f"{bogus_arn} does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The real environment must be unaffected by the failed call against the bogus name.
    env_final = batch.describe_service_environments(serviceEnvironments=[name])[
        "serviceEnvironments"
    ][0]
    assert env_final["state"] == "DISABLED", f"expected DISABLED, got {env_final['state']!r}"
    assert env_final["capacityLimits"][0]["maxCapacity"] == 10, (
        f"expected maxCapacity 10, got {env_final['capacityLimits']}"
    )


def _client_error(fn) -> Any:
    """Call fn() expecting an AWS refusal; return its (Error.Code, Error.Message)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _wait_for_status(ctx, name: str, terminal_statuses: set[str], timeout_s: float = 120.0):
    batch = ctx.client("batch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = batch.describe_service_environments(serviceEnvironments=[name])
        envs = resp.get("serviceEnvironments", [])
        if envs:
            last = envs[0]
            if last["status"] in terminal_statuses:
                return last
        time.sleep(3)
    raise AssertionError(
        f"service environment {name} never reached a terminal status within {timeout_s}s "
        f"(last seen: {last})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
