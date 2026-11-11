"""telemetry-rule-update-persists-configuration."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "telemetry-rule-update-persists-configuration"
GROUP = "state"
SERVICES = ["observabilityadmin"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:observabilityadmin-telemetry-evaluation")
def run(ctx) -> None:
    """UpdateTelemetryRule replaces the rule's DestinationConfiguration and the change is
    visible on a subsequent GetTelemetryRule, while the RuleArn stays stable across the
    update."""
    client = ctx.client("observabilityadmin")
    _ensure_telemetry_evaluation(client)
    name = ctx.unique_name("sim2real-oa-rule-")

    rule = {
        "ResourceType": "AWS::Bedrock::KnowledgeBase",
        "TelemetryType": "Logs",
        "DestinationConfiguration": {
            "DestinationType": "cloud-watch-logs",
            "RetentionInDays": 7,
            "LogDeliveryParameters": {"LogTypes": ["APPLICATION_LOGS"]},
        },
    }
    created = client.create_telemetry_rule(
        RuleName=name, Rule=rule, Tags={"sim2real": "telemetry-rule-update-persists-configuration"}
    )
    rule_arn = created["RuleArn"]
    ctx.on_cleanup(lambda: _delete_ignore_not_found(client, rule_arn))

    updated_rule = dict(rule)
    updated_rule["DestinationConfiguration"] = {
        "DestinationType": "cloud-watch-logs",
        "RetentionInDays": 30,
        "LogDeliveryParameters": {"LogTypes": ["APPLICATION_LOGS"]},
    }
    updated = client.update_telemetry_rule(RuleIdentifier=rule_arn, Rule=updated_rule)
    assert updated["RuleArn"] == rule_arn, f"expected update response RuleArn {rule_arn!r}, got {updated['RuleArn']!r}"

    got = client.get_telemetry_rule(RuleIdentifier=rule_arn)
    assert got["RuleArn"] == rule_arn, f"expected GetTelemetryRule RuleArn {rule_arn!r}, got {got['RuleArn']!r}"
    got_retention = got["TelemetryRule"]["DestinationConfiguration"]["RetentionInDays"]
    assert got_retention == 30, (
        f"expected UpdateTelemetryRule's new RetentionInDays (30) to persist and be visible on a "
        f"subsequent GetTelemetryRule, got {got_retention!r}"
    )


def _ensure_telemetry_evaluation(client, timeout_s=300.0, interval_s=5.0):
    status = client.get_telemetry_evaluation_status().get("Status")
    if status == "RUNNING":
        return
    if status in (None, "NOT_STARTED", "STOPPED", "FAILED_START", "FAILED_STOP"):
        try:
            # Regions/AllRegions are for multi-region onboarding; the current region is
            # always implicitly included and the API rejects it if named explicitly.
            client.start_telemetry_evaluation()
        except ClientError as e:
            if e.response["Error"]["Code"] != "ConflictException":
                raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = client.get_telemetry_evaluation_status().get("Status")
        if status == "RUNNING":
            return
        if status == "FAILED_START":
            raise AssertionError("telemetry evaluation failed to start")
        time.sleep(interval_s)
    raise AssertionError(f"telemetry evaluation never reached RUNNING (last={status})")


def _delete_ignore_not_found(client, rule_arn: str) -> None:
    try:
        client.delete_telemetry_rule(RuleIdentifier=rule_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
