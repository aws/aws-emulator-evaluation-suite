"""predefined-deployment-strategy-catalogue."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "predefined-deployment-strategy-catalogue"
GROUP = 'deployment-strategy'
SERVICES = ['appconfig']

MAX_PAGES = 20  # bounded pagination; ListDeploymentStrategies caps MaxResults at 50

# The four AWS-predefined deployment strategies and the exact parameter values AWS returns.
PREDEFINED = {
    "AppConfig.AllAtOnce": {
        "Description": "Quick",
        "DeploymentDurationInMinutes": 0,
        "FinalBakeTimeInMinutes": 10,
        "GrowthFactor": 100.0,
        "GrowthType": "LINEAR",
        "ReplicateTo": "NONE",
    },
    "AppConfig.Linear50PercentEvery30Seconds": {
        "Description": "Test/Demo",
        "DeploymentDurationInMinutes": 1,
        "FinalBakeTimeInMinutes": 1,
        "GrowthFactor": 50.0,
        "GrowthType": "LINEAR",
        "ReplicateTo": "NONE",
    },
    "AppConfig.Canary10Percent20Minutes": {
        "Description": "AWS Recommended",
        "DeploymentDurationInMinutes": 20,
        "FinalBakeTimeInMinutes": 10,
        "GrowthFactor": 10.0,
        "GrowthType": "EXPONENTIAL",
        "ReplicateTo": "NONE",
    },
    "AppConfig.Linear20PercentEvery6Minutes": {
        "Description": "AWS Recommended",
        "DeploymentDurationInMinutes": 30,
        "FinalBakeTimeInMinutes": 30,
        "GrowthFactor": 20.0,
        "GrowthType": "LINEAR",
        "ReplicateTo": "NONE",
    },
}

def _error_code(fn):
    """Return (Error.Code, Error.Message) from the ClientError fn() raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _list_all_strategies(ac) -> list:
    """Fully paginate ListDeploymentStrategies within MAX_PAGES, two items per page."""
    out, token, pages = [], None, 0
    while pages < MAX_PAGES:
        pages += 1
        page = ac.list_deployment_strategies(
            MaxResults=2, **({"NextToken": token} if token else {})
        )
        items = page.get("Items", [])
        assert len(items) <= 2, f"MaxResults=2 was not honored: {len(items)} items returned"
        out.extend(items)
        token = page.get("NextToken")
        if not token:
            return out
    raise AssertionError(
        f"ListDeploymentStrategies did not terminate within {MAX_PAGES} pages"
    )


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The four predefined deployment strategies are listed and resolvable by id with exact
    parameter values, and UpdateDeploymentStrategy on one is refused with BadRequestException and
    changes nothing, while the same update on a caller-created strategy succeeds.

    Reference: https://docs.aws.amazon.com/appconfig/latest/userguide/appconfig-creating-deployment-strategy.html
    """
    ac = ctx.client("appconfig")

    listed = _list_all_strategies(ac)
    by_id = {}
    for item in listed:
        assert item["Id"] not in by_id, (
            f"ListDeploymentStrategies returned duplicate id {item['Id']!r} across pages"
        )
        by_id[item["Id"]] = item

    missing = sorted(set(PREDEFINED) - set(by_id))
    assert not missing, (
        f"ListDeploymentStrategies is missing AWS-predefined strategies {missing} — these are "
        f"reference data present in every real account; an emulator that knows only "
        f"caller-created strategies fails here (it listed: {sorted(by_id)})"
    )

    for strategy_id, expected in PREDEFINED.items():
        # The predefined strategies are named after themselves.
        listed_item = by_id[strategy_id]
        assert listed_item["Name"] == strategy_id, (
            f"{strategy_id}: Name must equal Id, got {listed_item['Name']!r}"
        )

        # Resolving by the literal id must return the same record as the listing.
        got = ac.get_deployment_strategy(DeploymentStrategyId=strategy_id)
        assert got["Id"] == strategy_id, f"{strategy_id}: GetDeploymentStrategy echoed {got['Id']!r}"
        assert got["Name"] == strategy_id, f"{strategy_id}: {got['Name']!r}"

        for field, value in expected.items():
            assert got[field] == value, (
                f"{strategy_id}.{field}: expected {value!r}, got {got.get(field)!r} — the "
                f"predefined strategies' parameters are fixed AWS facts, not defaults the "
                f"emulator may choose"
            )
            assert listed_item.get(field) == value, (
                f"{strategy_id}.{field}: the listing disagrees with GetDeploymentStrategy "
                f"({listed_item.get(field)!r} vs {value!r})"
            )

        # Float-typed GrowthFactor: 100 and 100.0 compare equal in Python, so pin the type
        # too. An emulator serialising it as an integer changes the JSON on the wire.
        assert isinstance(got["GrowthFactor"], float), (
            f"{strategy_id}: GrowthFactor is a float in the model; got "
            f"{type(got['GrowthFactor']).__name__}"
        )

    # Positive control: the update works on a caller-created strategy, so the refusal below is
    # specific to predefined strategies.
    own_name = ctx.unique_name("sim2real-behav-predef-ctl-")
    own_id = ac.create_deployment_strategy(
        Name=own_name,
        DeploymentDurationInMinutes=10,
        GrowthFactor=5.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=own_id))
    own_updated = ac.update_deployment_strategy(DeploymentStrategyId=own_id, GrowthFactor=25.0)
    assert own_updated["GrowthFactor"] == 25.0, (
        f"positive control: UpdateDeploymentStrategy on a caller-created strategy must succeed "
        f"and persist the new value, got {own_updated.get('GrowthFactor')!r} — without this, a "
        f"target that rejects EVERY update would pass the immutability negative below for the "
        f"wrong reason"
    )

    # The predefined strategies are immutable.
    canary = "AppConfig.Canary10Percent20Minutes"
    before = ac.get_deployment_strategy(DeploymentStrategyId=canary)
    code, message = _error_code(
        lambda: ac.update_deployment_strategy(
            DeploymentStrategyId=canary,
            DeploymentDurationInMinutes=5,
            GrowthType="LINEAR",
        )
    )
    assert code == "BadRequestException", (
        f"UpdateDeploymentStrategy on the AWS-predefined {canary} must be refused with "
        f"BadRequestException, got {code!r} — an emulator that lets a caller re-parameterise "
        f"a predefined strategy silently changes the meaning of every template that names it"
    )
    assert message == f"Cannot update predefined Deployment Strategy {before['Id']}", (
        f"expected the exact BadRequestException message AWS returns, got {message!r}"
    )

    # The refused update changed nothing.
    after = ac.get_deployment_strategy(DeploymentStrategyId=canary)
    for field, value in PREDEFINED[canary].items():
        assert after[field] == value, (
            f"the refused UpdateDeploymentStrategy mutated {canary}.{field}: "
            f"{before.get(field)!r} -> {after.get(field)!r} (expected {value!r})"
        )

    after_ids = {s["Id"] for s in _list_all_strategies(ac)}
    assert after_ids >= set(PREDEFINED), (
        f"the predefined catalogue must be unchanged by a refused update; now missing "
        f"{sorted(set(PREDEFINED) - after_ids)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
