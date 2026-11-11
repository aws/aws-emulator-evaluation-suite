"""list-deployment-configs-includes-created-and-predefined."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "list-deployment-configs-includes-created-and-predefined"
GROUP = 'lifecycle'
SERVICES = ['codedeploy']

def _create_deployment_config(ctx, *, min_healthy_type="HOST_COUNT", min_healthy_value=1):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-dpcfg-")
    cd.create_deployment_config(
        deploymentConfigName=name,
        computePlatform="Server",
        minimumHealthyHosts={"type": min_healthy_type, "value": min_healthy_value},
    )
    ctx.on_cleanup(lambda: cd.delete_deployment_config(deploymentConfigName=name))
    return name


def _error(fn):
    """(code, message) of the ClientError fn() raises. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=30, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDeploymentConfigs lists a created config next to CodeDeployDefault.OneAtATime, and after deletion
    GetDeploymentConfig fails with DeploymentConfigDoesNotExistException and the exact not-found message.
    """
    cd = ctx.client("codedeploy")

    throttle_codes = {"ThrottlingException", "Throttling", "RequestLimitExceeded"}

    def _names() -> "set[str] | None":
        acc: set[str] = set()
        try:
            for page in cd.get_paginator("list_deployment_configs").paginate():
                acc.update(page.get("deploymentConfigsList", []))
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in throttle_codes:
                return None
            raise
        return acc

    name = _create_deployment_config(ctx)

    names = _poll_until(
        probe=_names,
        predicate=lambda names: names is not None and name in names,
        description=f"{name} appears in ListDeploymentConfigs after create",
    )
    assert "CodeDeployDefault.OneAtATime" in names, "predefined config missing from list"

    cd.delete_deployment_config(deploymentConfigName=name)

    _poll_until(
        probe=_names,
        predicate=lambda names: names is not None and name not in names,
        description=f"{name} absent from ListDeploymentConfigs after delete",
    )

    code, message = _error(lambda: cd.get_deployment_config(deploymentConfigName=name))
    assert code == "DeploymentConfigDoesNotExistException", (
        f"expected DeploymentConfigDoesNotExistException after delete, got {code!r}"
    )
    assert message == f"No deployment configuration found for name: {name}", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
