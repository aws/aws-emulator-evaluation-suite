"""matchmaking-configuration-unknown-ruleset-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "matchmaking-configuration-unknown-ruleset-rejected"
GROUP = "overly-permissive"
SERVICES = ["gamelift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateMatchmakingConfiguration naming a rule set that does not exist is rejected with InvalidRequestException
    and its exact message and creates nothing, while the same request naming an existing rule set succeeds.
    """
    gl = ctx.client("gamelift")
    bad_config_name = ctx.unique_name("sim2real-mmcfg-bad-")
    bogus_ruleset = ctx.unique_name("sim2real-nonexistent-ruleset-")

    code, message = _error(
        lambda: gl.create_matchmaking_configuration(
            Name=bad_config_name,
            RuleSetName=bogus_ruleset,
            RequestTimeoutSeconds=30,
            AcceptanceRequired=False,
            FlexMatchMode="STANDALONE",
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    expected_message = f"RuleSet with name {bogus_ruleset} does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    described_code, described_message = _error(
        lambda: gl.describe_matchmaking_configurations(Names=[bad_config_name])
    )
    assert described_code == "InvalidRequestException", (
        f"expected DescribeMatchmakingConfigurations({bad_config_name!r}) to also raise "
        f"InvalidRequestException for a never-created configuration, got {described_code!r}"
    )
    expected_described = f"Configuration not found: {bad_config_name}"
    assert described_message == expected_described, (
        f"expected message {expected_described!r}, got {described_message!r}"
    )

    # Positive control: create a real rule set and reference it successfully.
    ruleset_name = ctx.unique_name("sim2real-mmcfg-ruleset-")
    gl.create_matchmaking_rule_set(
        Name=ruleset_name,
        RuleSetBody=json.dumps(
            {
                "name": "control",
                "ruleLanguageVersion": "1.0",
                "teams": [{"name": "solo", "minPlayers": 1, "maxPlayers": 2}],
            }
        ),
    )
    ctx.on_cleanup(lambda: gl.delete_matchmaking_rule_set(Name=ruleset_name))

    good_config_name = ctx.unique_name("sim2real-mmcfg-good-")
    good = gl.create_matchmaking_configuration(
        Name=good_config_name,
        RuleSetName=ruleset_name,
        RequestTimeoutSeconds=30,
        AcceptanceRequired=False,
        FlexMatchMode="STANDALONE",
    )["Configuration"]
    ctx.on_cleanup(lambda: gl.delete_matchmaking_configuration(Name=good_config_name))
    assert good["RuleSetName"] == ruleset_name, (
        f"create response should echo RuleSetName {ruleset_name!r}, got {good['RuleSetName']!r}"
    )

    # Independent terminal read: the real ruleset reference is durable and visible
    # through Describe, not just echoed by the Create response.
    described_good = gl.describe_matchmaking_configurations(Names=[good_config_name])[
        "Configurations"
    ][0]
    assert described_good["RuleSetName"] == ruleset_name, (
        f"Describe({good_config_name!r}) should show RuleSetName {ruleset_name!r}, "
        f"got {described_good['RuleSetName']!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
