"""delete-predefined-deployment-strategies-rejected-each-fields-unchanged."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-predefined-deployment-strategies-rejected-each-fields-unchanged"
GROUP = "deployment-strategy"
SERVICES = ["appconfig"]

PREDEFINED_IDS = (
    "AppConfig.AllAtOnce",
    "AppConfig.Linear50PercentEvery30Seconds",
    "AppConfig.Canary10Percent20Minutes",
    "AppConfig.Linear20PercentEvery6Minutes",
)
UNCHANGED_FIELDS = (
    "Name",
    "DeploymentDurationInMinutes",
    "GrowthFactor",
    "GrowthType",
    "FinalBakeTimeInMinutes",
)


def _error_code_and_message(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn() raises; raise on success."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` is forgiven."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _all_strategy_ids(ac) -> set:
    """Every DeploymentStrategyId ListDeploymentStrategies lists, across all pages."""
    pages = ac.get_paginator("list_deployment_strategies").paginate(
        PaginationConfig={"PageSize": 2}
    )
    return {item["Id"] for page in pages for item in page["Items"]}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteDeploymentStrategy on every predefined strategy is refused with
    BadRequestException and its fields are unchanged afterward, while a caller-created
    strategy deletes and both Get and ListDeploymentStrategies reflect that, predefined ids included.
    """
    ac = ctx.client("appconfig")

    for strategy_id in PREDEFINED_IDS:
        before = ac.get_deployment_strategy(DeploymentStrategyId=strategy_id)

        code, message = _error_code_and_message(
            lambda sid=strategy_id: ac.delete_deployment_strategy(DeploymentStrategyId=sid)
        )
        assert code == "BadRequestException", (
            f"{strategy_id}: expected BadRequestException deleting a predefined strategy, got {code!r}"
        )
        expected_message = f"Cannot delete predefined Deployment Strategy {strategy_id}."
        assert message == expected_message, (
            f"{strategy_id}: expected {expected_message!r}, got {message!r}"
        )

        after = ac.get_deployment_strategy(DeploymentStrategyId=strategy_id)
        for field in UNCHANGED_FIELDS:
            assert after[field] == before[field], (
                f"{strategy_id}.{field}: a rejected delete changed it from {before[field]!r} "
                f"to {after[field]!r}"
            )

    custom_name = ctx.unique_name("sim2real-behav-ds-")
    custom_id = ac.create_deployment_strategy(
        Name=custom_name,
        DeploymentDurationInMinutes=15,
        GrowthFactor=40.0,
        GrowthType="LINEAR",
        FinalBakeTimeInMinutes=5,
        ReplicateTo="NONE",
        Tags={"sim2real-check": CHECK},
    )["Id"]
    ctx.on_cleanup(
        _teardown(
            lambda: ac.delete_deployment_strategy(DeploymentStrategyId=custom_id),
            "ResourceNotFoundException",
        )
    )

    listed_before_delete = _all_strategy_ids(ac)
    assert custom_id in listed_before_delete, (
        f"the caller-created strategy {custom_id!r} is missing from ListDeploymentStrategies "
        f"before it was deleted"
    )

    ac.delete_deployment_strategy(DeploymentStrategyId=custom_id)

    get_code, get_message = _error_code_and_message(
        lambda: ac.get_deployment_strategy(DeploymentStrategyId=custom_id)
    )
    assert get_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading the deleted caller-created strategy, got {get_code!r}"
    )
    expected_not_found = f"DeploymentStrategy with Id {custom_id} could not be found."
    assert get_message == expected_not_found, f"expected {expected_not_found!r}, got {get_message!r}"

    listed_after_delete = _all_strategy_ids(ac)
    assert custom_id not in listed_after_delete, (
        f"the deleted caller-created strategy {custom_id!r} is still listed by "
        f"ListDeploymentStrategies: {sorted(listed_after_delete)!r}"
    )
    missing_predefined = sorted(set(PREDEFINED_IDS) - listed_after_delete)
    assert not missing_predefined, (
        f"ListDeploymentStrategies dropped predefined id(s) {missing_predefined} after an "
        f"unrelated caller strategy was deleted"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
