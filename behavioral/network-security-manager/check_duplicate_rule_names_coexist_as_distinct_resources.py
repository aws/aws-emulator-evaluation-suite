"""duplicate-rule-names-coexist-as-distinct-resources."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-rule-names-coexist-as-distinct-resources"
GROUP = "representation"
SERVICES = ["network-security-manager"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ruleName is not a uniqueness key: two rules sharing the same name coexist as
    distinct resources, each addressed and updated independently by its own ARN.
    """
    nsm = ctx.client("network-security-manager")
    shared_name = ctx.unique_name("sim2real-behav-nsm-dup-")

    first = nsm.create_rule(
        ruleName=shared_name,
        firewallType="WAF",
        ruleType="CONFIGURATION",
        configuration={"DefaultAction": {"Allow": {}}},
        isPublished=True,
    )
    first_arn = first["ruleArn"]
    ctx.on_cleanup(
        _teardown(lambda: nsm.delete_rule(ruleIdentifier=first_arn), "ResourceNotFoundException")
    )

    second = nsm.create_rule(
        ruleName=shared_name,
        firewallType="WAF",
        ruleType="CONFIGURATION",
        configuration={"DefaultAction": {"Block": {}}},
        isPublished=True,
    )
    second_arn = second["ruleArn"]
    ctx.on_cleanup(
        _teardown(lambda: nsm.delete_rule(ruleIdentifier=second_arn), "ResourceNotFoundException")
    )

    assert first["ruleId"] != second["ruleId"], (
        f"two creates with the same name produced the same ruleId {first['ruleId']!r}"
    )
    assert first_arn != second_arn, "two creates with the same name produced the same ARN"

    # Each is independently addressable: reading one never reflects the other's configuration.
    got_first = nsm.get_rule(ruleIdentifier=first_arn)
    got_second = nsm.get_rule(ruleIdentifier=second_arn)
    assert got_first["ruleName"] == shared_name and got_second["ruleName"] == shared_name, (
        "both rules should report the shared name"
    )
    assert got_first["configuration"] == {"DefaultAction": {"Allow": {}}}, (
        f"first rule's configuration changed to {got_first['configuration']!r}"
    )
    assert got_second["configuration"] == {"DefaultAction": {"Block": {}}}, (
        f"second rule's configuration changed to {got_second['configuration']!r}"
    )

    # Both are independently listed, not merged into one entry.
    seen_ids = set()
    paginator = nsm.get_paginator("list_rules")
    for page in paginator.paginate(status="ACTIVE"):
        seen_ids.update(r["ruleId"] for r in page["rules"])
    assert {first["ruleId"], second["ruleId"]} <= seen_ids, (
        f"ListRules did not include both rule ids {first['ruleId']!r} and {second['ruleId']!r}"
    )

    # Updating one by its own ARN never touches the other.
    nsm.update_rule(
        ruleIdentifier=first_arn,
        updateToken=first["updateToken"],
        isPublished=True,
        configuration={"DefaultAction": {"Block": {}}},
    )
    unaffected = nsm.get_rule(ruleIdentifier=second_arn)
    assert unaffected["configuration"] == {"DefaultAction": {"Block": {}}}, (
        f"updating the first rule changed the second rule's configuration to "
        f"{unaffected['configuration']!r}"
    )
    assert unaffected["version"] == "1", (
        f"updating the first rule bumped the second rule's version to {unaffected['version']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
