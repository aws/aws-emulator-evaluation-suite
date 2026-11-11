"""op-contract-createDeploymentStrategy."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-createDeploymentStrategy"
GROUP = "error-semantics"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDeploymentStrategy returns the exact echoed fields, which are durable on an
    independent read; GrowthFactor out of [1.0, 100.0] is rejected with BadRequestException and
    no strategy is created."""
    appconfig = ctx.client("appconfig")
    name = ctx.unique_name("sim2real-ds-")
    resp = appconfig.create_deployment_strategy(
        Name=name,
        DeploymentDurationInMinutes=10,
        GrowthFactor=25.5,
        GrowthType="LINEAR",
        FinalBakeTimeInMinutes=5,
        ReplicateTo="NONE",
        Tags={"sim2real:managed": "true", "sim2real": "create-deployment-strategy-contract"},
    )
    strategy_id = resp["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))

    assert resp["Name"] == name, f"expected Name {name!r}, got {resp['Name']!r}"
    assert resp["DeploymentDurationInMinutes"] == 10, (
        f"expected DeploymentDurationInMinutes 10, got {resp['DeploymentDurationInMinutes']!r}"
    )
    assert resp["GrowthFactor"] == 25.5, f"expected GrowthFactor 25.5, got {resp['GrowthFactor']!r}"
    assert resp["GrowthType"] == "LINEAR", f"expected GrowthType LINEAR, got {resp['GrowthType']!r}"
    assert resp["FinalBakeTimeInMinutes"] == 5, (
        f"expected FinalBakeTimeInMinutes 5, got {resp['FinalBakeTimeInMinutes']!r}"
    )
    assert resp["ReplicateTo"] == "NONE", f"expected ReplicateTo NONE, got {resp['ReplicateTo']!r}"

    # independent read: the echoed fields are stored, not just reflected back on the mutating call
    got = appconfig.get_deployment_strategy(DeploymentStrategyId=strategy_id)
    assert got["Name"] == name, f"expected stored Name {name!r}, got {got['Name']!r}"
    assert got["GrowthFactor"] == 25.5, f"expected stored GrowthFactor 25.5, got {got['GrowthFactor']!r}"
    assert got["GrowthType"] == "LINEAR", f"expected stored GrowthType LINEAR, got {got['GrowthType']!r}"

    # error boundary: break exactly one thing relative to the positive control above --
    # GrowthFactor above the valid 1.0-100.0 range, every other field unchanged.
    bad_name = ctx.unique_name("sim2real-ds-bad-")
    code, message = _error(
        lambda: appconfig.create_deployment_strategy(
            Name=bad_name,
            DeploymentDurationInMinutes=10,
            GrowthFactor=150.0,
            GrowthType="LINEAR",
            FinalBakeTimeInMinutes=5,
            ReplicateTo="NONE",
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    expected = (
        "1 validation error detected: Value '150.0' at 'growthFactor' failed to satisfy "
        "constraint: Member must have value less than or equal to 100.0"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # the rejected call must not have created a resource under that name
    listed = appconfig.list_deployment_strategies(MaxResults=50)["Items"]
    assert all(item["Name"] != bad_name for item in listed), (
        f"rejected GrowthFactor=150.0 must not create a strategy named {bad_name!r}, but it "
        f"appeared in ListDeploymentStrategies: {listed!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (Error Code, Error Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
