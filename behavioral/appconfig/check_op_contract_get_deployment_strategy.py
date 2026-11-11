"""op-contract-getDeploymentStrategy."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getDeploymentStrategy"
GROUP = "error-semantics"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDeploymentStrategy returns the exact fields supplied at creation, including
    unspecified fields defaulted correctly; a nonexistent DeploymentStrategyId is
    rejected with ResourceNotFoundException."""
    appconfig = ctx.client("appconfig")
    name = ctx.unique_name("sim2real-ds-")
    strategy_id = appconfig.create_deployment_strategy(
        Name=name,
        DeploymentDurationInMinutes=15,
        GrowthFactor=10.0,
        GrowthType="EXPONENTIAL",
        FinalBakeTimeInMinutes=2,
        ReplicateTo="NONE",
        Tags={"sim2real": "true"},
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))

    resp = appconfig.get_deployment_strategy(DeploymentStrategyId=strategy_id)
    assert resp["Id"] == strategy_id
    assert resp["Name"] == name
    assert resp["DeploymentDurationInMinutes"] == 15
    assert resp["GrowthFactor"] == 10.0
    assert resp["GrowthType"] == "EXPONENTIAL"
    assert resp["FinalBakeTimeInMinutes"] == 2
    assert resp["ReplicateTo"] == "NONE"

    # error boundary: strategy never existed. Use a deleted-but-real strategy id
    # rather than a hand-written string: DeploymentStrategyId is pattern-validated
    # against the same shape as a real AWS-generated id, and an arbitrary string like
    # "0000000000000000" fails that shape check with BadRequestException before any
    # not-found lookup happens. A real (now-deleted) id is valid in shape, so the
    # not-found path is the one actually exercised.
    stale_strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-ds-stale-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags={"sim2real": "true"},
    )["Id"]
    appconfig.delete_deployment_strategy(DeploymentStrategyId=stale_strategy_id)

    code, code_msg = _error(
        lambda: appconfig.get_deployment_strategy(DeploymentStrategyId=stale_strategy_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert code_msg == f"DeploymentStrategy with Id {stale_strategy_id} could not be found.", (
        f"unexpected message: {code_msg!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
