"""deployment-strategy-minutes-upper-bound-matrix."""
from __future__ import annotations

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "deployment-strategy-minutes-upper-bound-matrix"
GROUP = 'deployment-strategy'
SERVICES = ['appconfig']

# MinutesBetween0And24Hours: integer, min 0, max 1440. Only maximums are tested: botocore
# enforces @range minimums client-side, so a below-minimum value never reaches the service.
MAX_MINUTES = 1440
MAX_GROWTH_FACTOR = 100.0

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-deployment-strategy"}


def _client_error(fn):
    """Call fn(); return (code, message) of its ClientError, raising if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _all_strategy_names(ac) -> set:
    """Every deployment strategy name in the account, fully paginated with a bounded loop."""
    names, token, pages = set(), None, 0
    while pages < 50:
        pages += 1
        page = ac.list_deployment_strategies(
            MaxResults=50, **({"NextToken": token} if token else {})
        )
        names.update(s["Name"] for s in page.get("Items", []))
        token = page.get("NextToken")
        if not token:
            return names
    raise AssertionError("ListDeploymentStrategies did not terminate within 50 pages")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """1440 minutes is accepted and stored on both deployment-strategy minute fields while 1441 is
    refused with an exact message and creates nothing; UpdateDeploymentStrategy enforces it too.
    """
    ac = ctx.client("appconfig")

    at_limit_name = ctx.unique_name("sim2real-behav-ds-max-")
    at_limit = ac.create_deployment_strategy(
        Name=at_limit_name,
        DeploymentDurationInMinutes=MAX_MINUTES,
        FinalBakeTimeInMinutes=MAX_MINUTES,
        GrowthFactor=MAX_GROWTH_FACTOR,
        GrowthType="EXPONENTIAL",
        ReplicateTo="NONE",
        Tags=_TAGS,
    )
    at_limit_id = at_limit["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=at_limit_id))

    assert at_limit["DeploymentDurationInMinutes"] == MAX_MINUTES, (
        f"the create response must echo the accepted boundary value, got "
        f"{at_limit['DeploymentDurationInMinutes']!r}"
    )
    assert at_limit["FinalBakeTimeInMinutes"] == MAX_MINUTES, at_limit["FinalBakeTimeInMinutes"]
    assert at_limit["GrowthFactor"] == MAX_GROWTH_FACTOR, at_limit["GrowthFactor"]
    assert isinstance(at_limit["GrowthFactor"], float), (
        f"GrowthFactor is a float in the model; got {type(at_limit['GrowthFactor']).__name__}"
    )
    assert at_limit["GrowthType"] == "EXPONENTIAL", at_limit["GrowthType"]

    stored = ac.get_deployment_strategy(DeploymentStrategyId=at_limit_id)
    assert stored["DeploymentDurationInMinutes"] == MAX_MINUTES, stored
    assert stored["FinalBakeTimeInMinutes"] == MAX_MINUTES, stored
    assert stored["GrowthFactor"] == MAX_GROWTH_FACTOR, stored
    assert stored["GrowthType"] == "EXPONENTIAL", stored

    names_before = _all_strategy_names(ac)
    assert at_limit_name in names_before, (
        "the accepted boundary strategy must appear in ListDeploymentStrategies"
    )

    over_duration_name = ctx.unique_name("sim2real-behav-ds-over-dur-")
    code_duration, message_duration = _client_error(
        lambda: ac.create_deployment_strategy(
            Name=over_duration_name,
            DeploymentDurationInMinutes=MAX_MINUTES + 1,
            FinalBakeTimeInMinutes=0,
            GrowthFactor=MAX_GROWTH_FACTOR,
            ReplicateTo="NONE",
        )
    )
    assert code_duration == "BadRequestException", (
        f"DeploymentDurationInMinutes={MAX_MINUTES + 1} is one past the modeled maximum and "
        f"must be refused with BadRequestException, not clamped to {MAX_MINUTES}; got "
        f"{code_duration!r}"
    )
    expected_duration = (
        f"1 validation error detected: Value '{MAX_MINUTES + 1}' at 'deploymentDurationInMinutes' failed to "
        f"satisfy constraint: Member must have value less than or equal to {MAX_MINUTES}"
    )
    assert message_duration == expected_duration, (
        f"expected {expected_duration!r}, got {message_duration!r}"
    )

    over_bake_name = ctx.unique_name("sim2real-behav-ds-over-bake-")
    code_bake, message_bake = _client_error(
        lambda: ac.create_deployment_strategy(
            Name=over_bake_name,
            DeploymentDurationInMinutes=0,
            FinalBakeTimeInMinutes=MAX_MINUTES + 1,
            GrowthFactor=MAX_GROWTH_FACTOR,
            ReplicateTo="NONE",
        )
    )
    assert code_bake == "BadRequestException", (
        f"FinalBakeTimeInMinutes={MAX_MINUTES + 1} must be refused with BadRequestException; "
        f"got {code_bake!r} — the field has an upper bound the service must enforce"
    )
    expected_bake = (
        f"1 validation error detected: Value '{MAX_MINUTES + 1}' at 'finalBakeTimeInMinutes' failed to "
        f"satisfy constraint: Member must have value less than or equal to {MAX_MINUTES}"
    )
    assert message_bake == expected_bake, f"expected {expected_bake!r}, got {message_bake!r}"

    names_after = _all_strategy_names(ac)
    leaked = {over_duration_name, over_bake_name} & names_after
    assert not leaked, (
        f"a refused CreateDeploymentStrategy must create nothing; these names appeared in "
        f"ListDeploymentStrategies anyway: {sorted(leaked)}"
    )
    assert at_limit_name in names_after, (
        "the accepted boundary strategy must survive the two refusals"
    )

    code_update, message_update = _client_error(
        lambda: ac.update_deployment_strategy(
            DeploymentStrategyId=at_limit_id,
            FinalBakeTimeInMinutes=MAX_MINUTES + 1,
        )
    )
    assert code_update == "BadRequestException", (
        f"UpdateDeploymentStrategy must enforce the same {MAX_MINUTES}-minute ceiling as "
        f"create; got {code_update!r} — an emulator that validates only on create is a real "
        f"over-permissiveness gap"
    )
    assert message_update == expected_bake, (
        f"expected {expected_bake!r}, got {message_update!r}"
    )
    unchanged = ac.get_deployment_strategy(DeploymentStrategyId=at_limit_id)
    assert unchanged["FinalBakeTimeInMinutes"] == MAX_MINUTES, (
        f"the refused update must not mutate the strategy; FinalBakeTimeInMinutes is now "
        f"{unchanged['FinalBakeTimeInMinutes']!r}"
    )

    # An in-range update succeeds, so the refusal above was specific to the value.
    ac.update_deployment_strategy(
        DeploymentStrategyId=at_limit_id, FinalBakeTimeInMinutes=MAX_MINUTES - 1
    )
    updated = ac.get_deployment_strategy(DeploymentStrategyId=at_limit_id)
    assert updated["FinalBakeTimeInMinutes"] == MAX_MINUTES - 1, (
        f"an in-range update must persist; got {updated['FinalBakeTimeInMinutes']!r}"
    )
    assert updated["DeploymentDurationInMinutes"] == MAX_MINUTES, (
        f"a partial update must not reset unmentioned fields; DeploymentDurationInMinutes is "
        f"now {updated['DeploymentDurationInMinutes']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
