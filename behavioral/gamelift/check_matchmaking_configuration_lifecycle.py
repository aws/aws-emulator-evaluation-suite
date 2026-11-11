"""matchmaking-configuration-lifecycle."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "matchmaking-configuration-lifecycle"
GROUP = "state"
SERVICES = ["gamelift"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateMatchmakingConfiguration changes BackfillMode from MANUAL to AUTOMATIC as Describe shows; after
    the delete, Describe and Update fail with their exact errors and the name can be created again.
    """
    gl = ctx.client("gamelift")
    resource_tags = [{"Key": "env", "Value": "sim2real"}, {"Key": "owner", "Value": "behavioral"}]
    ruleset_name = ctx.unique_name("sim2real-mmlife-ruleset-")
    gl.create_matchmaking_rule_set(
        Name=ruleset_name,
        RuleSetBody=json.dumps(
            {
                "name": "lifecycle",
                "ruleLanguageVersion": "1.0",
                "teams": [{"name": "solo", "minPlayers": 1, "maxPlayers": 2}],
            }
        ),
        Tags=resource_tags,
    )
    ctx.on_cleanup(lambda: gl.delete_matchmaking_rule_set(Name=ruleset_name))

    config_name = ctx.unique_name("sim2real-mmlife-cfg-")
    created = gl.create_matchmaking_configuration(
        Name=config_name,
        RuleSetName=ruleset_name,
        RequestTimeoutSeconds=30,
        AcceptanceRequired=False,
        BackfillMode="MANUAL",
        FlexMatchMode="STANDALONE",
        Tags=resource_tags,
    )["Configuration"]
    assert created["BackfillMode"] == "MANUAL", f"expected MANUAL on create, got {created['BackfillMode']!r}"

    updated = gl.update_matchmaking_configuration(Name=config_name, BackfillMode="AUTOMATIC")[
        "Configuration"
    ]
    assert updated["BackfillMode"] == "AUTOMATIC", (
        f"expected AUTOMATIC on update response, got {updated['BackfillMode']!r}"
    )

    described = gl.describe_matchmaking_configurations(Names=[config_name])["Configurations"][0]
    assert described["BackfillMode"] == "AUTOMATIC", (
        f"expected AUTOMATIC on independent Describe, got {described['BackfillMode']!r}"
    )

    gl.delete_matchmaking_configuration(Name=config_name)
    after_code, after_message = _error(lambda: gl.describe_matchmaking_configurations(Names=[config_name]))
    assert after_code == "InvalidRequestException", (
        f"expected InvalidRequestException on Describe of a deleted configuration, got {after_code!r}"
    )
    expected_after = f"Configuration not found: {config_name}"
    assert after_message == expected_after, f"expected message {expected_after!r}, got {after_message!r}"

    update_after_delete_code, update_after_delete_message = _error(
        lambda: gl.update_matchmaking_configuration(Name=config_name, BackfillMode="MANUAL")
    )
    assert update_after_delete_code == "NotFoundException", (
        "expected Update on a deleted configuration to also fail -- with "
        f"NotFoundException (Describe uses InvalidRequestException instead), got {update_after_delete_code!r}"
    )
    expected_update = f"Configuration with name {config_name} does not exist"
    assert update_after_delete_message == expected_update, (
        f"expected message {expected_update!r}, got {update_after_delete_message!r}"
    )

    recreated = gl.create_matchmaking_configuration(
        Name=config_name,
        RuleSetName=ruleset_name,
        RequestTimeoutSeconds=30,
        AcceptanceRequired=False,
        BackfillMode="MANUAL",
        FlexMatchMode="STANDALONE",
        Tags=resource_tags,
    )["Configuration"]
    ctx.on_cleanup(lambda: gl.delete_matchmaking_configuration(Name=config_name))
    assert recreated["Name"] == config_name, (
        f"expected the freed configuration name to be reusable, got {recreated['Name']!r}"
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
