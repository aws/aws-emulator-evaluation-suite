"""automated-reasoning-policy-definition-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "automated-reasoning-policy-definition-round-trip"
GROUP = "server-side"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The types, variables and rules of a policy definition passed to
    CreateAutomatedReasoningPolicy come back identical from ExportAutomatedReasoningPolicyVersion,
    the operation that returns the full definition.
    """
    bedrock = ctx.client("bedrock")
    name = ctx.unique_name("sim2real-behav-arpolicy-")

    # Rules use the SMT-LIB-subset syntax Automated Reasoning checks require
    # (if-then rules connected with "=>"), and variable types are one of the
    # fixed set BOOL/INT/NUMBER (not arbitrary strings like "bool"/"real").
    definition = {
        "version": "1.0",
        "variables": [
            {
                "name": "isRaining",
                "type": "BOOL",
                "description": "Whether it is currently raining outside.",
            },
            {
                "name": "temperature",
                "type": "NUMBER",
                "description": "The current outdoor temperature in degrees Celsius.",
            },
        ],
        "types": [],
        "rules": [
            {
                "id": "R00000000001",
                "expression": "(=> isRaining (< temperature 30))",
                "alternateExpression": "If it's raining, the temperature is below 30C.",
            },
            {
                "id": "R00000000002",
                "expression": "(=> (< temperature 0) (not isRaining))",
                "alternateExpression": "Below freezing implies it is not raining.",
            },
        ],
    }

    created = bedrock.create_automated_reasoning_policy(name=name, policyDefinition=definition)
    policy_arn = created["policyArn"]
    ctx.on_cleanup(lambda: bedrock.delete_automated_reasoning_policy(policyArn=policy_arn))

    exported = bedrock.export_automated_reasoning_policy_version(policyArn=policy_arn)["policyDefinition"]

    # The "version" field is a format-version marker that AWS may normalize/assign
    # server-side rather than echo verbatim, so this checks the actual policy content
    # (variables, types, rules) survives round-trip byte-identically, not that field.
    assert exported["types"] == definition["types"], (
        f"expected types {definition['types']!r}, got {exported['types']!r}"
    )

    exported_vars = {v["name"]: v for v in exported["variables"]}
    for expected_var in definition["variables"]:
        actual = exported_vars[expected_var["name"]]
        assert actual["type"] == expected_var["type"], (
            f"variable {expected_var['name']!r}: expected type "
            f"{expected_var['type']!r}, got {actual['type']!r}"
        )
        assert actual["description"] == expected_var["description"], (
            f"variable {expected_var['name']!r}: expected description "
            f"{expected_var['description']!r}, got {actual['description']!r}"
        )

    exported_rules = {r["id"]: r for r in exported["rules"]}
    for expected_rule in definition["rules"]:
        actual = exported_rules[expected_rule["id"]]
        assert actual["expression"] == expected_rule["expression"], (
            f"rule {expected_rule['id']!r}: expected expression "
            f"{expected_rule['expression']!r}, got {actual['expression']!r}"
        )
        assert actual["alternateExpression"] == expected_rule["alternateExpression"], (
            f"rule {expected_rule['id']!r}: expected alternateExpression "
            f"{expected_rule['alternateExpression']!r}, got {actual['alternateExpression']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
