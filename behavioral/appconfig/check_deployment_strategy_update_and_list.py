"""deployment-strategy-update-and-list."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployment-strategy-update-and-list"
GROUP = "deployment-strategy"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Full CRUD lifecycle of a custom deployment strategy; membership verified via ListDeploymentStrategies."""
    appconfig = ctx.client("appconfig")
    name = ctx.unique_name("sim2real-ds-")

    created = appconfig.create_deployment_strategy(
        Name=name,
        DeploymentDurationInMinutes=10,
        GrowthFactor=10.0,
        GrowthType="LINEAR",
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
    )
    ds_id = created["Id"]
    assert created["DeploymentDurationInMinutes"] == 10, (
        f"expected DeploymentDurationInMinutes=10 on create, got {created['DeploymentDurationInMinutes']!r}"
    )
    assert created["GrowthFactor"] == 10.0, f"expected GrowthFactor=10.0 on create, got {created['GrowthFactor']!r}"
    ctx.on_cleanup(lambda: _safe_delete_strategy(appconfig, ds_id))

    got = appconfig.get_deployment_strategy(DeploymentStrategyId=ds_id)
    assert got["Name"] == name, f"expected Name={name!r}, got {got['Name']!r}"
    assert got["GrowthType"] == "LINEAR", f"expected GrowthType=LINEAR, got {got['GrowthType']!r}"

    updated = appconfig.update_deployment_strategy(
        DeploymentStrategyId=ds_id,
        DeploymentDurationInMinutes=20,
        GrowthFactor=25.0,
        FinalBakeTimeInMinutes=5,
    )
    assert updated["DeploymentDurationInMinutes"] == 20, (
        f"expected DeploymentDurationInMinutes=20 on update, got {updated['DeploymentDurationInMinutes']!r}"
    )
    assert updated["GrowthFactor"] == 25.0, f"expected GrowthFactor=25.0 on update, got {updated['GrowthFactor']!r}"
    assert updated["FinalBakeTimeInMinutes"] == 5, (
        f"expected FinalBakeTimeInMinutes=5 on update, got {updated['FinalBakeTimeInMinutes']!r}"
    )

    got2 = appconfig.get_deployment_strategy(DeploymentStrategyId=ds_id)
    assert got2["DeploymentDurationInMinutes"] == 20, (
        f"expected DeploymentDurationInMinutes=20 after update, got {got2['DeploymentDurationInMinutes']!r}"
    )
    assert got2["GrowthFactor"] == 25.0, f"expected GrowthFactor=25.0 after update, got {got2['GrowthFactor']!r}"

    items = _list_all_strategies(appconfig)
    match = next((i for i in items if i["Id"] == ds_id), None)
    assert match is not None, "deployment strategy not found in ListDeploymentStrategies"
    assert match["GrowthFactor"] == 25.0, f"expected listed GrowthFactor=25.0, got {match['GrowthFactor']!r}"

    appconfig.delete_deployment_strategy(DeploymentStrategyId=ds_id)

    items_after = _list_all_strategies(appconfig)
    assert all(i["Id"] != ds_id for i in items_after), "deleted strategy still listed"

    not_found = f"DeploymentStrategy with Id {ds_id} could not be found."
    mutate_code, mutate_message = _client_error(
        lambda: appconfig.update_deployment_strategy(DeploymentStrategyId=ds_id, DeploymentDurationInMinutes=1)
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected a mutation on a deleted strategy to be rejected with ResourceNotFoundException, got {mutate_code}"
    )
    assert mutate_message == not_found, f"expected {not_found!r}, got {mutate_message!r}"

    code, message = _client_error(
        lambda: appconfig.get_deployment_strategy(DeploymentStrategyId=ds_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == not_found, f"expected {not_found!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return (code, message) of its botocore ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_strategy(appconfig, ds_id):
    try:
        appconfig.delete_deployment_strategy(DeploymentStrategyId=ds_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _list_all_strategies(appconfig):
    items = []
    kwargs = {}
    while True:
        resp = appconfig.list_deployment_strategies(**kwargs)
        items.extend(resp.get("Items", []))
        token = resp.get("NextToken")
        if not token:
            break
        kwargs = {"NextToken": token}
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
