"""op-contract-deleteDeploymentStrategy."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteDeploymentStrategy"
GROUP = "error-semantics"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDeploymentStrategy removes the strategy (positive control); a second delete
    on the now-absent strategy is rejected with ResourceNotFoundException and the
    strategy remains absent from GetDeploymentStrategy and the account listing."""
    appconfig = ctx.client("appconfig")

    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-ds-"),
        DeploymentDurationInMinutes=5,
        GrowthFactor=50.0,
    )["Id"]
    ctx.on_cleanup(lambda: _delete_strategy_if_present(appconfig, strategy_id))
    not_found = f"DeploymentStrategy with Id {strategy_id} could not be found."

    # positive control: strategy is readable before deletion
    appconfig.get_deployment_strategy(DeploymentStrategyId=strategy_id)

    appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id)

    code, message = _error(
        lambda: appconfig.get_deployment_strategy(DeploymentStrategyId=strategy_id)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetDeploymentStrategy after delete, got {code}"
    )
    assert message == not_found, f"expected message {not_found!r}, got {message!r}"
    listed = appconfig.list_deployment_strategies(MaxResults=50)["Items"]
    assert all(item["Id"] != strategy_id for item in listed), (
        f"deleted strategy {strategy_id} still present in ListDeploymentStrategies"
    )

    # negative: deleting the already-deleted strategy is rejected, effect stays absent
    code, message = _error(
        lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == not_found, f"expected message {not_found!r}, got {message!r}"

    # terminal independent read: the rejected double-delete must not have resurrected it
    final_code, final_message = _error(
        lambda: appconfig.get_deployment_strategy(DeploymentStrategyId=strategy_id)
    )
    assert final_code == "ResourceNotFoundException", (
        f"strategy {strategy_id} must remain absent after the rejected double-delete, got {final_code}"
    )
    assert final_message == not_found, f"expected message {not_found!r}, got {final_message!r}"


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of its ClientError. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


def _delete_strategy_if_present(appconfig, strategy_id):
    """Teardown: the check deletes the strategy itself, so an absent one is the expected end."""
    try:
        appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
