"""deployment-strategy-invalid-growth-factor-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployment-strategy-invalid-growth-factor-rejected"
GROUP = 'overly-permissive'
SERVICES = ['appconfig']


def _client_error(fn):
    """Call fn(); return (code, message) of its botocore ClientError. An unexpected SUCCESS
    raises, because a target ACCEPTING a call real AWS refuses must not be reported as an
    error-code mismatch."""
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeploymentStrategy with GrowthFactor 150, outside [1.0, 100.0], is rejected rather than clamped or
    accepted, while the identical call with a valid GrowthFactor succeeds."""
    ac = ctx.client("appconfig")

    # Positive control: the identical call shape, an in-range GrowthFactor.
    good_name = ctx.unique_name("sim2real-behav-ds-good-")
    good = ac.create_deployment_strategy(
        Name=good_name,
        DeploymentDurationInMinutes=10,
        GrowthFactor=50.0,
    )
    good_id = good["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=good_id))
    assert good["GrowthFactor"] == 50.0, (
        f"the positive control did not create with GrowthFactor=50.0: {good!r}"
    )

    names_before = _all_strategy_names(ac)
    assert good_name in names_before, (
        "the positive control must appear in ListDeploymentStrategies before the rejection"
    )

    # Break exactly one thing: GrowthFactor above its modeled maximum of 100.0.
    bad_name = ctx.unique_name("sim2real-behav-ds-bad-")
    code, message = _client_error(
        lambda: ac.create_deployment_strategy(
            Name=bad_name,
            DeploymentDurationInMinutes=10,
            GrowthFactor=150,
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    expected = (
        "1 validation error detected: Value '150.0' at 'growthFactor' failed to satisfy "
        "constraint: Member must have value less than or equal to 100.0"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # Effect absent, via an independent read at the destination: the rejected call created
    # nothing, and the unrelated positive control survives untouched.
    names_after = _all_strategy_names(ac)
    assert bad_name not in names_after, (
        f"a refused CreateDeploymentStrategy(GrowthFactor=150) must create nothing; "
        f"{bad_name!r} appeared in ListDeploymentStrategies anyway"
    )
    assert good_name in names_after, (
        "the rejection of GrowthFactor=150 must not remove the unrelated positive control"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
