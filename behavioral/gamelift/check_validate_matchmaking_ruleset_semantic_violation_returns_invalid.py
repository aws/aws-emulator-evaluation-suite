"""validate-matchmaking-ruleset-semantic-violation-returns-invalid."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "validate-matchmaking-ruleset-semantic-violation-returns-invalid"
GROUP = "data-plane"
SERVICES = ["gamelift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ValidateMatchmakingRuleSet rejects valid JSON that lacks the required teams element with
    InvalidRequestException and its exact message, and returns Valid=True for a conforming rule set.
    """
    gl = ctx.client("gamelift")

    semantically_broken = json.dumps({"name": "missing_teams", "ruleLanguageVersion": "1.0"})
    code, message = _error(lambda: gl.validate_matchmaking_rule_set(RuleSetBody=semantically_broken))
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException for a rule set missing the required "
        f"'teams' element, got {code!r}"
    )
    expected_message = "Rule set does not define team definitions; location: top level"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    valid_body = json.dumps(
        {
            "name": "well_formed",
            "ruleLanguageVersion": "1.0",
            "teams": [{"name": "solo", "minPlayers": 1, "maxPlayers": 2}],
        }
    )
    valid_result = gl.validate_matchmaking_rule_set(RuleSetBody=valid_body)
    assert valid_result["Valid"] is True, (
        f"expected Valid=True for a schema-conformant rule set, got {valid_result!r}"
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

