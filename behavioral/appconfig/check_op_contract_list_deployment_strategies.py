"""op-contract-listDeploymentStrategies."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listDeploymentStrategies"
GROUP = "error-semantics"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDeploymentStrategies lists a new strategy with its exact growth parameters and rejects a
    malformed NextToken with BadRequestException; after delete the strategy is unlisted and
    Get/UpdateDeploymentStrategy fail with ResourceNotFoundException."""
    appconfig = ctx.client("appconfig")
    name = ctx.unique_name("sim2real-ds-")
    strategy_id = appconfig.create_deployment_strategy(
        Name=name,
        DeploymentDurationInMinutes=20,
        GrowthFactor=33.5,
        GrowthType="LINEAR",
        Tags={"sim2real-check": "list-deployment-strategies-contract"},
    )["Id"]
    ctx.on_cleanup(lambda: _safe_delete(appconfig, strategy_id))

    items = _all_strategies(appconfig)
    by_id = {i["Id"]: i for i in items}
    assert strategy_id in by_id, "created strategy missing from ListDeploymentStrategies"
    assert by_id[strategy_id]["Name"] == name
    assert by_id[strategy_id]["GrowthType"] == "LINEAR"
    assert by_id[strategy_id]["GrowthFactor"] == 33.5

    bad_token = "not-a-real-pagination-token!!"
    err = _error(lambda: appconfig.list_deployment_strategies(NextToken=bad_token))
    assert err["Code"] == "BadRequestException", f"expected BadRequestException, got {err['Code']}"
    assert err["Message"] == f"Invalid nextToken parameter {bad_token}.", (
        f"unexpected message: {err['Message']!r}"
    )

    appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id)

    items_after = _all_strategies(appconfig)
    assert all(i["Id"] != strategy_id for i in items_after), (
        "deleted strategy still present in ListDeploymentStrategies"
    )

    not_found = f"DeploymentStrategy with Id {strategy_id} could not be found."
    get_err = _error(
        lambda: appconfig.get_deployment_strategy(DeploymentStrategyId=strategy_id)
    )
    assert get_err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetDeploymentStrategy on a deleted id, got {get_err['Code']}"
    )
    assert get_err["Message"] == not_found, f"unexpected GetDeploymentStrategy message: {get_err['Message']!r}"

    update_err = _error(
        lambda: appconfig.update_deployment_strategy(
            DeploymentStrategyId=strategy_id, GrowthFactor=50.0
        )
    )
    assert update_err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from UpdateDeploymentStrategy on a deleted id, got {update_err['Code']}"
    )
    assert update_err["Message"] == not_found, (
        f"unexpected UpdateDeploymentStrategy message: {update_err['Message']!r}"
    )


def _all_strategies(appconfig) -> list:
    """Every deployment strategy ListDeploymentStrategies lists, across all pages."""
    pages = appconfig.get_paginator("list_deployment_strategies").paginate(PaginationConfig={"PageSize": 50})
    return [item for page in pages for item in page["Items"]]


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete(appconfig, strategy_id):
    try:
        appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
