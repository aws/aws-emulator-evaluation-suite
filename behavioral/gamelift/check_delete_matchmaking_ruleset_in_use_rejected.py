"""delete-matchmaking-ruleset-in-use-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "delete-matchmaking-ruleset-in-use-rejected"
GROUP = "overly-permissive"
SERVICES = ["gamelift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteMatchmakingRuleSet is rejected with InvalidRequestException and its exact message while a matchmaking
    configuration uses the rule set, which stays describable; an unused rule set deletes, and so does this one once
    the configuration is deleted (Describe then fails with 'Failed to find rule set: <name>').
    """
    gl = ctx.client("gamelift")

    # Positive control: deleting an unreferenced rule set works, so a rejection below
    # is attributable to the reference, not to DeleteMatchmakingRuleSet itself.
    unused_ruleset = ctx.unique_name("sim2real-mmdel-unused-")
    gl.create_matchmaking_rule_set(
        Name=unused_ruleset,
        RuleSetBody=json.dumps(
            {
                "name": "unused",
                "ruleLanguageVersion": "1.0",
                "teams": [{"name": "solo", "minPlayers": 1, "maxPlayers": 2}],
            }
        ),
        Tags=[{"Key": "env", "Value": "sim2real"}, {"Key": "owner", "Value": "behavioral"}],
    )
    gl.delete_matchmaking_rule_set(Name=unused_ruleset)
    gone_code, gone_message = _error(lambda: gl.describe_matchmaking_rule_sets(Names=[unused_ruleset]))
    assert gone_code == "InvalidRequestException", (
        f"unreferenced rule set should already be gone, got {gone_code!r}"
    )
    expected_gone = f"Failed to find rule set: {unused_ruleset}"
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"

    # Break: reference the rule set from a matchmaking configuration.
    in_use_ruleset = ctx.unique_name("sim2real-mmdel-inuse-")
    gl.create_matchmaking_rule_set(
        Name=in_use_ruleset,
        RuleSetBody=json.dumps(
            {
                "name": "in_use",
                "ruleLanguageVersion": "1.0",
                "teams": [{"name": "solo", "minPlayers": 1, "maxPlayers": 2}],
            }
        ),
        Tags=[{"Key": "env", "Value": "sim2real"}, {"Key": "owner", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: gl.delete_matchmaking_rule_set(Name=in_use_ruleset)))
    config_name = ctx.unique_name("sim2real-mmdel-cfg-")
    gl.create_matchmaking_configuration(
        Name=config_name,
        RuleSetName=in_use_ruleset,
        RequestTimeoutSeconds=30,
        AcceptanceRequired=False,
        FlexMatchMode="STANDALONE",
        Tags=[{"Key": "env", "Value": "sim2real"}, {"Key": "owner", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: gl.delete_matchmaking_configuration(Name=config_name)))

    code, message = _error(lambda: gl.delete_matchmaking_rule_set(Name=in_use_ruleset))
    assert code == "InvalidRequestException", f"expected the in-use delete rejected, got {code!r}"
    expected_message = "Matchmaking rule set is still in use, cannot delete"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the in-use rule set is still there, untouched.
    still_there = gl.describe_matchmaking_rule_sets(Names=[in_use_ruleset])["RuleSets"]
    assert len(still_there) == 1, "in-use rule set should still be fully describable after the rejected delete"

    # Restore: remove the referencing configuration, then retry the identical call.
    gl.delete_matchmaking_configuration(Name=config_name)
    gl.delete_matchmaking_rule_set(Name=in_use_ruleset)
    after_restore_code, after_restore_message = _error(
        lambda: gl.describe_matchmaking_rule_sets(Names=[in_use_ruleset])
    )
    assert after_restore_code == "InvalidRequestException", (
        f"expected the rule set gone once its only reference is removed, got {after_restore_code!r}"
    )
    expected_after = f"Failed to find rule set: {in_use_ruleset}"
    assert after_restore_message == expected_after, (
        f"expected message {expected_after!r}, got {after_restore_message!r}"
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


def _ignore_not_found(fn):
    """Teardown: run fn(), tolerating a resource the check already deleted."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
