"""telemetry-rule-duplicate-name-conflict-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "telemetry-rule-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["observabilityadmin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:observabilityadmin-telemetry-evaluation")
def run(ctx) -> None:
    """CreateTelemetryRule with an existing RuleName fails with ConflictException "Telemetry Rule already
    exists." and leaves the original rule's resource type; a distinct name and configuration create a
    second rule."""
    client = ctx.client("observabilityadmin")
    _ensure_telemetry_evaluation(ctx, client)
    name = ctx.unique_name("sim2real-oa-dup-")

    tags = {"sim2real-check": CHECK}
    base_rule = {"ResourceType": "AWS::Bedrock::KnowledgeBase", "TelemetryType": "Logs"}
    created = client.create_telemetry_rule(RuleName=name, Rule=base_rule, Tags=tags)
    rule_arn = created["RuleArn"]
    ctx.on_cleanup(lambda: _delete_ignore_not_found(client, rule_arn))

    conflicting_rule = {"ResourceType": "AWS::EC2::VPC", "TelemetryType": "Logs"}
    code, message = _client_error(
        lambda: client.create_telemetry_rule(RuleName=name, Rule=conflicting_rule)
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    assert message == "Telemetry Rule already exists.", (
        f"expected the conflict message 'Telemetry Rule already exists.', got {message!r}"
    )

    # effect absent: the original rule's configuration was not overwritten by the conflicting attempt
    got = client.get_telemetry_rule(RuleIdentifier=rule_arn)
    actual_type = got["TelemetryRule"]["ResourceType"]
    assert actual_type == "AWS::Bedrock::KnowledgeBase", (
        f"expected original ResourceType AWS::Bedrock::KnowledgeBase to survive the "
        f"rejected conflicting create, got {actual_type!r}"
    )

    # positive control: creating with a distinct, unused name succeeds
    other_name = ctx.unique_name("sim2real-oa-dup-ctrl-")
    other = client.create_telemetry_rule(RuleName=other_name, Rule=conflicting_rule, Tags=tags)
    other_arn = other["RuleArn"]
    ctx.on_cleanup(lambda: _delete_ignore_not_found(client, other_arn))
    assert other_arn != rule_arn, (
        f"expected a fresh RuleArn for the distinct name, got the same arn {other_arn!r}"
    )


def _ensure_telemetry_evaluation(ctx, client, timeout_s=300.0, interval_s=5.0):
    status = client.get_telemetry_evaluation_status().get("Status")
    if status == "RUNNING":
        return
    # Telemetry evaluation is an account setting: one this check starts is stopped again.
    ctx.on_cleanup(lambda: _stop_telemetry_evaluation(client))
    if status in (None, "NOT_STARTED", "STOPPED", "FAILED_START", "FAILED_STOP"):
        try:
            # Regions must not name the current region: it is always implicit.
            client.start_telemetry_evaluation()
        except ClientError as e:
            if e.response["Error"]["Code"] != "ConflictException":
                raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        evaluation_status = client.get_telemetry_evaluation_status()
        status = evaluation_status.get("Status")
        if status == "RUNNING":
            return
        if status == "FAILED_START":
            raise AssertionError(
                f"telemetry evaluation failed to start: {evaluation_status.get('FailureReason')!r}"
            )
        time.sleep(interval_s)
    raise AssertionError(f"telemetry evaluation never reached RUNNING (last={status})")


def _stop_telemetry_evaluation(client, timeout_s=300.0, interval_s=5.0):
    client.stop_telemetry_evaluation()
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = client.get_telemetry_evaluation_status().get("Status")
        if status in ("STOPPED", "FAILED_STOP"):
            assert status == "STOPPED", "telemetry evaluation failed to stop"
            return
        time.sleep(interval_s)
    raise AssertionError(f"telemetry evaluation never reached STOPPED (last={status})")


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
