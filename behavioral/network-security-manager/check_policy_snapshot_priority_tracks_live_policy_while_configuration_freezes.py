"""policy-snapshot-priority-tracks-live-policy-while-configuration-freezes."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "policy-snapshot-priority-tracks-live-policy-while-configuration-freezes"
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
    """A policy snapshot's version and policyConfiguration freeze at creation, but its
    priority keeps reporting the live policy's current priority, not the one at snapshot time.
    """
    nsm = ctx.client("network-security-manager")
    rule_name = ctx.unique_name("sim2real-behav-nsm-polsnaprule-")
    policy_name = ctx.unique_name("sim2real-behav-nsm-polsnap-")

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

    policy = nsm.create_policy(
        policyName=policy_name,
        priority=5,
        firewallType="WAF",
        associatedTemplateAndRuleList=[{"ruleIdentifier": rule_arn}],
        policyConfiguration={
            "remediationEnabled": False,
            "resourcesCleanUp": True,
            "wafConfig": {
                "existingCustomerWebACLResolution": "NO_REMEDIATION",
                "conflictResolution": "MERGE_WHERE_APPLICABLE",
            },
        },
        isPublished=True,
    )
    policy_arn = policy["policyArn"]
    ctx.on_cleanup(
        _teardown(
            lambda: nsm.delete_policy(policyIdentifier=policy_arn), "ResourceNotFoundException"
        )
    )

    snapshot = nsm.create_policy_snapshot(policyIdentifier=policy_arn)
    snapshot_arn = snapshot["policyArn"]
    assert snapshot["version"] == "1", (
        f"snapshot was taken at version {snapshot['version']!r}, expected '1'"
    )
    assert snapshot["priority"] == 5, (
        f"snapshot should read priority 5 at creation, got {snapshot['priority']!r}"
    )

    nsm.update_policy(
        policyIdentifier=policy_arn,
        updateToken=policy["updateToken"],
        isPublished=True,
        priority=50,
        policyConfiguration={
            "remediationEnabled": True,
            "resourcesCleanUp": True,
            "wafConfig": {
                "existingCustomerWebACLResolution": "NO_REMEDIATION",
                "conflictResolution": "MERGE_WHERE_APPLICABLE",
            },
        },
    )

    live = nsm.get_policy(policyIdentifier=policy_arn)
    assert live["version"] == "2", (
        f"live policy should be version '2' after the update, got {live['version']!r}"
    )
    assert live["priority"] == 50, f"live policy priority should be 50, got {live['priority']!r}"
    assert live["policyConfiguration"]["remediationEnabled"] is True, (
        "live policy should reflect remediationEnabled=True after the update"
    )

    frozen = nsm.get_policy(policyIdentifier=snapshot_arn)
    assert frozen["version"] == "1", (
        f"the snapshot's version must stay '1' after the live policy was updated, got {frozen['version']!r}"
    )
    assert frozen["policyConfiguration"]["remediationEnabled"] is False, (
        "the snapshot's policyConfiguration must stay frozen at remediationEnabled=False, "
        f"got {frozen['policyConfiguration']['remediationEnabled']!r}"
    )
    assert frozen["priority"] == 50, (
        "the snapshot's priority must track the live policy's current priority (50), "
        f"got {frozen['priority']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
