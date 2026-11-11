"""create-matchmaking-ruleset-malformed-json-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "create-matchmaking-ruleset-malformed-json-rejected"
GROUP = "overly-permissive"
SERVICES = ["gamelift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateMatchmakingRuleSet rejects a RuleSetBody that is not valid JSON with
    InvalidRequestException and persists nothing, while a syntactically valid body
    submitted in the same run is accepted (positive control)."""
    gl = ctx.client("gamelift")
    bad_name = ctx.unique_name("sim2real-ruleset-bad-")

    code, message = _error(
        lambda: gl.create_matchmaking_rule_set(
            Name=bad_name, RuleSetBody="{not valid json at all"
        )
    )
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException creating a rule set with malformed "
        f"RuleSetBody, got {code!r}"
    )
    expected_message = "Encountered IOException attempting to extract version; location: top level"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: describing a rule set name that was never created is rejected
    # with InvalidRequestException (a descriptive "failed to find" message) rather
    # than silently returning an empty list.
    describe_code, describe_message = _error(lambda: gl.describe_matchmaking_rule_sets(Names=[bad_name]))
    assert describe_code == "InvalidRequestException", (
        f"expected InvalidRequestException describing never-created rule set "
        f"{bad_name!r}, got {describe_code!r}"
    )
    expected_describe = f"Failed to find rule set: {bad_name}"
    assert describe_message == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_message!r}"
    )

    # Positive control: a well-formed rule set with the same shape of request succeeds.
    good_name = ctx.unique_name("sim2real-ruleset-good-")
    good_body = json.dumps(
        {
            "name": "control_ruleset",
            "ruleLanguageVersion": "1.0",
            "teams": [{"name": "solo", "minPlayers": 1, "maxPlayers": 2}],
        }
    )
    created = gl.create_matchmaking_rule_set(Name=good_name, RuleSetBody=good_body)["RuleSet"]
    ctx.on_cleanup(lambda: gl.delete_matchmaking_rule_set(Name=good_name))
    assert created["RuleSetName"] == good_name, (
        f"expected positive-control create to return RuleSetName={good_name!r}, "
        f"got {created.get('RuleSetName')!r}"
    )

    # Terminal assertion is an independent read (Describe), not the mutating
    # Create call's own response: the good rule set is actually visible at the
    # destination, distinguishing acceptance from a call that merely didn't error.
    described = gl.describe_matchmaking_rule_sets(Names=[good_name])["RuleSets"][0]
    assert described["RuleSetName"] == good_name, (
        f"expected independent describe to find positive-control rule set "
        f"{good_name!r}, got {described.get('RuleSetName')!r}"
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
