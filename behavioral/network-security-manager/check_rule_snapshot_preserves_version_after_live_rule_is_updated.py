"""rule-snapshot-preserves-version-after-live-rule-is-updated."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rule-snapshot-preserves-version-after-live-rule-is-updated"
GROUP = "snapshot-immutability"
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
    """A rule snapshot freezes the configuration and version in effect when it was taken;
    updating the live rule afterward never changes what the snapshot reads back.
    """
    nsm = ctx.client("network-security-manager")
    rule_name = ctx.unique_name("sim2real-behav-nsm-rule-")

    rule = nsm.create_rule(
        ruleName=rule_name,
        firewallType="WAF",
        ruleType="CONFIGURATION",
        configuration={"DefaultAction": {"Allow": {}}},
        isPublished=True,
    )
    rule_arn = rule["ruleArn"]
    ctx.on_cleanup(
        _teardown(lambda: nsm.delete_rule(ruleIdentifier=rule_arn), "ResourceNotFoundException")
    )

    snapshot = nsm.create_rule_snapshot(ruleIdentifier=rule_arn)
    snapshot_arn = snapshot["ruleArn"]
    assert snapshot["version"] == "1", (
        f"snapshot was taken at version {snapshot['version']!r}, expected '1'"
    )
    assert snapshot_arn != rule_arn, (
        f"the snapshot's ARN {snapshot_arn!r} must differ from the live rule's ARN {rule_arn!r}"
    )

    nsm.update_rule(
        ruleIdentifier=rule_arn,
        updateToken=rule["updateToken"],
        isPublished=True,
        configuration={"DefaultAction": {"Block": {}}},
    )

    live = nsm.get_rule(ruleIdentifier=rule_arn)
    assert live["version"] == "2", (
        f"live rule should be version '2' after the update, got {live['version']!r}"
    )
    assert live["configuration"] == {"DefaultAction": {"Block": {}}}, (
        f"live rule configuration should reflect the update, got {live['configuration']!r}"
    )

    frozen = nsm.get_rule(ruleIdentifier=snapshot_arn)
    assert frozen["version"] == "1", (
        f"the snapshot must stay at version '1' after the live rule was updated, got {frozen['version']!r}"
    )
    assert frozen["configuration"] == {"DefaultAction": {"Allow": {}}}, (
        f"the snapshot's configuration changed to {frozen['configuration']!r}, "
        "but a snapshot must be immutable"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
