"""op-contract-updateDeploymentStrategy."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-updateDeploymentStrategy"
GROUP = "error-semantics"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDeploymentStrategy persists new duration/growth/bake-time values,
    visible via GetDeploymentStrategy, while the immutable Name is untouched;
    updating a nonexistent DeploymentStrategyId yields ResourceNotFoundException."""
    appconfig = ctx.client("appconfig")

    name = ctx.unique_name("sim2real-behav-strat-")
    strategy_id = appconfig.create_deployment_strategy(
        Name=name,
        DeploymentDurationInMinutes=10,
        GrowthFactor=5.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags={"sim2real-check": CHECK},
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))

    updated = appconfig.update_deployment_strategy(
        DeploymentStrategyId=strategy_id,
        Description="updated-strategy",
        DeploymentDurationInMinutes=20,
        GrowthFactor=25.0,
        FinalBakeTimeInMinutes=5,
    )
    assert updated["DeploymentDurationInMinutes"] == 20, (
        f"expected DeploymentDurationInMinutes 20, got {updated['DeploymentDurationInMinutes']}"
    )
    assert updated["GrowthFactor"] == 25.0, f"expected GrowthFactor 25.0, got {updated['GrowthFactor']}"
    assert updated["FinalBakeTimeInMinutes"] == 5, (
        f"expected FinalBakeTimeInMinutes 5, got {updated['FinalBakeTimeInMinutes']}"
    )
    assert updated["Description"] == "updated-strategy", (
        f"expected Description 'updated-strategy', got {updated['Description']!r}"
    )
    assert updated["Name"] == name, (
        f"Name is immutable and must be unaffected by the update: expected {name!r}, "
        f"got {updated['Name']!r}"
    )

    fetched = appconfig.get_deployment_strategy(DeploymentStrategyId=strategy_id)
    assert fetched["DeploymentDurationInMinutes"] == 20, (
        f"independent read: expected DeploymentDurationInMinutes 20, got {fetched['DeploymentDurationInMinutes']}"
    )
    assert fetched["GrowthFactor"] == 25.0, (
        f"independent read: expected GrowthFactor 25.0, got {fetched['GrowthFactor']}"
    )
    assert fetched["FinalBakeTimeInMinutes"] == 5, (
        f"independent read: expected FinalBakeTimeInMinutes 5, got {fetched['FinalBakeTimeInMinutes']}"
    )

    err = _error(
        lambda: appconfig.update_deployment_strategy(
            DeploymentStrategyId="0000000", DeploymentDurationInMinutes=1
        )
    )
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err}"
    expected_message = "DeploymentStrategy with Id 0000000 could not be found."
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(
        f"expected a ClientError, but the call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
