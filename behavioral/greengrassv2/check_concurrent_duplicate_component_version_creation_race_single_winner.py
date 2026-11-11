"""concurrent-duplicate-component-version-creation-race-single-winner."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-duplicate-component-version-creation-race-single-winner"
GROUP = "concurrency"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Racing CreateComponentVersion calls for the same name and version with distinct client tokens
    yield exactly one winner; every other racer raises ConflictException with the exact message.
    """
    gg = ctx.client("greengrassv2")
    name = ctx.unique_name("sim2real-ggv2-race-")
    version = "1.0.0"
    recipe = _make_recipe(name, version)
    racer_count = 6

    def _attempt(i: int):
        try:
            resp = gg.create_component_version(
                inlineRecipe=recipe,
                clientToken=f"sim2real-race-{i}-{name}",
                tags={"env": "sim2real-behavioral"},
            )
            return ("ok", resp["arn"])
        except ClientError as e:
            return (e.response["Error"]["Code"], e.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(_attempt, i) for i in range(racer_count)]
        results = [f.result() for f in as_completed(futures)]

    winners = [r for r in results if r[0] == "ok"]
    losers = [r for r in results if r[0] != "ok"]

    assert len(winners) == 1, f"expected exactly one winner, got {len(winners)}: {results}"
    assert len(losers) == racer_count - 1, (
        f"expected {racer_count - 1} losers, got {len(losers)}: {results}"
    )
    assert all(code == "ConflictException" for code, _ in losers), f"unexpected loser codes: {losers}"

    winning_arn = winners[0][1]
    ctx.on_cleanup(lambda: _delete_ignore_missing(gg, winning_arn))
    account = winning_arn.split(":")[4]
    expected = (
        f"Component [{name} : {version}] for account [{account}] already exists and can't be "
        "created again with tags."
    )
    for _, message in losers:
        assert message == expected, f"loser message {message!r}, expected {expected!r}"
    described = gg.describe_component(arn=winning_arn)
    assert described["componentVersion"] == version, (
        f"expected winner's independent read to report version {version!r}, "
        f"got {described['componentVersion']!r}"
    )


def _make_recipe(name: str, version: str) -> bytes:
    recipe = {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": version,
        "ComponentDescription": "concurrency race test component",
        "ComponentPublisher": "sim2real",
        "Manifests": [{"Platform": {"os": "linux"}, "Lifecycle": {}}],
    }
    return json.dumps(recipe).encode("utf-8")


def _delete_ignore_missing(gg, arn: str) -> None:
    try:
        gg.delete_component(arn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
