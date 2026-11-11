"""matchmaking-ruleset-create-and-validate-roundtrip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "matchmaking-ruleset-create-and-validate-roundtrip"
GROUP = "data-plane"
SERVICES = ["gamelift"]

_VALID_RULESET = {
    "name": "aliens_vs_cowboys",
    "ruleLanguageVersion": "1.0",
    "teams": [
        {"name": "cowboys", "minPlayers": 1, "maxPlayers": 4},
        {"name": "aliens", "minPlayers": 1, "maxPlayers": 4},
    ],
}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateMatchmakingRuleSet persists the exact RuleSetBody JSON supplied, and
    ValidateMatchmakingRuleSet on that same body reports it as syntactically and
    semantically Valid."""
    gl = ctx.client("gamelift")
    name = ctx.unique_name("sim2real-ruleset-")
    body = json.dumps(_VALID_RULESET)

    created = gl.create_matchmaking_rule_set(
        Name=name, RuleSetBody=body, Tags=[{"Key": "sim2real", "Value": "1"}]
    )["RuleSet"]
    ctx.on_cleanup(lambda: gl.delete_matchmaking_rule_set(Name=name))

    assert created["RuleSetName"] == name
    assert json.loads(created["RuleSetBody"]) == _VALID_RULESET

    described = gl.describe_matchmaking_rule_sets(Names=[name])["RuleSets"][0]
    assert json.loads(described["RuleSetBody"]) == _VALID_RULESET

    validation = gl.validate_matchmaking_rule_set(RuleSetBody=body)
    assert validation["Valid"] is True


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
