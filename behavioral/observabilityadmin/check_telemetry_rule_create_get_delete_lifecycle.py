"""telemetry-rule-create-get-delete-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "telemetry-rule-create-get-delete-lifecycle"
GROUP = "state"
SERVICES = ["observabilityadmin"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:observabilityadmin-telemetry-evaluation")
def run(ctx) -> None:
    """CreateTelemetryRule -> GetTelemetryRule round-trips nested DestinationConfiguration
    fields faithfully, and DeleteTelemetryRule removes the resource (subsequent Get raises
    ResourceNotFoundException)."""
    client = ctx.client("observabilityadmin")
    _ensure_telemetry_evaluation(ctx, client)
    name = ctx.unique_name("sim2real-oa-rule-")

    rule = {
        "ResourceType": "AWS::Bedrock::KnowledgeBase",
        "TelemetryType": "Logs",
        "DestinationConfiguration": {
            "DestinationType": "cloud-watch-logs",
            "RetentionInDays": 14,
            "LogDeliveryParameters": {"LogTypes": ["APPLICATION_LOGS"]},
        },
    }
    created = client.create_telemetry_rule(
        RuleName=name, Rule=rule, Tags={"sim2real:managed": "true"}
    )
    rule_arn = created["RuleArn"]
    ctx.on_cleanup(lambda: _delete_ignore_not_found(client, rule_arn))

    got = client.get_telemetry_rule(RuleIdentifier=rule_arn)
    assert got["RuleName"] == name, f"expected RuleName {name!r}, got {got['RuleName']!r}"
    assert got["RuleArn"] == rule_arn, (
        f"expected RuleArn {rule_arn!r}, got {got['RuleArn']!r}"
    )
    tr = got["TelemetryRule"]
    assert tr["ResourceType"] == "AWS::Bedrock::KnowledgeBase", (
        f"expected ResourceType 'AWS::Bedrock::KnowledgeBase', got {tr['ResourceType']!r}"
    )
    assert tr["TelemetryType"] == "Logs", (
        f"expected TelemetryType 'Logs', got {tr['TelemetryType']!r}"
    )
    dest = tr["DestinationConfiguration"]
    assert dest["DestinationType"] == "cloud-watch-logs", (
        f"expected DestinationType 'cloud-watch-logs', got {dest['DestinationType']!r}"
    )
    assert dest["RetentionInDays"] == 14, (
        f"expected RetentionInDays 14, got {dest['RetentionInDays']!r}"
    )
    assert dest["LogDeliveryParameters"]["LogTypes"] == ["APPLICATION_LOGS"], (
        f"expected LogDeliveryParameters.LogTypes ['APPLICATION_LOGS'], "
        f"got {dest.get('LogDeliveryParameters')!r}"
    )

    client.delete_telemetry_rule(RuleIdentifier=rule_arn)

    code, message = _client_error(lambda: client.get_telemetry_rule(RuleIdentifier=rule_arn))
    assert code == "ResourceNotFoundException", (
        f"expected GetTelemetryRule on a deleted rule to raise ResourceNotFoundException, "
        f"got {code!r}"
    )
    assert message == "Rule not found.", (
        f"expected the not-found message 'Rule not found.', got {message!r}"
    )


def _ensure_telemetry_evaluation(ctx, client, timeout_s=300.0, interval_s=5.0):
    status = client.get_telemetry_evaluation_status().get("Status")
    if status == "RUNNING":
        return
    if status in (None, "NOT_STARTED", "STOPPED", "FAILED_START", "FAILED_STOP"):
        _ensure_telemetry_enablement_slr(ctx)
        try:
            # Regions must NOT include the current region -- it is always implicit, and
            # passing it explicitly routes through multi-region enablement.
            client.start_telemetry_evaluation()
        except ClientError as e:
            if e.response["Error"]["Code"] != "ConflictException":
                raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = client.get_telemetry_evaluation_status()
        status = resp.get("Status")
        if status == "RUNNING":
            return
        if status == "FAILED_START":
            raise AssertionError(
                f"telemetry evaluation failed to start: {resp.get('FailureReason')!r} "
                f"region_statuses={resp.get('RegionStatuses')!r}"
            )
        time.sleep(interval_s)
    raise AssertionError(f"telemetry evaluation never reached RUNNING (last={status})")


def _ensure_telemetry_enablement_slr(ctx) -> None:
    # StartTelemetryEvaluation depends on the AWSServiceRoleForObservabilityAdmin_
    # TelemetryEnablement service-linked role. In some accounts the service fails to
    # auto-create it (surfaced as Status=FAILED_START, FailureReason=SLR_UNAVAILABLE) --
    # creating it explicitly up front works around that race.
    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(
            AWSServiceName="telemetry-enablement.observabilityadmin.amazonaws.com"
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInput":
            # InvalidInput covers "already exists" for CreateServiceLinkedRole; anything
            # else (e.g. AccessDenied) is a real problem worth surfacing.
            raise


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so a
    target that accepts a request real AWS refuses cannot pass as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_ignore_not_found(client, rule_arn: str) -> None:
    try:
        client.delete_telemetry_rule(RuleIdentifier=rule_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
