"""telemetry-rule-invalid-resource-type-enum-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "telemetry-rule-invalid-resource-type-enum-rejected"
GROUP = "overly-permissive"
SERVICES = ["observabilityadmin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:observabilityadmin-telemetry-evaluation")
def run(ctx) -> None:
    """CreateTelemetryRule rejects a ResourceType value outside the documented enum with
    ValidationException, no rule is created under that name, and the same call with a valid
    ResourceType succeeds (positive control)."""
    client = ctx.client("observabilityadmin")
    _ensure_telemetry_evaluation(client, ctx.region)
    bad_name = ctx.unique_name("sim2real-oa-badtype-")

    bad_rule = {"ResourceType": "AWS::TotallyBogus::NotAResource", "TelemetryType": "Logs"}
    # message varies: it lists the whole ResourceType enum, which grows as AWS adds types, so
    # the stable text before that list is asserted exactly.
    code, message = _client_error(
        lambda: client.create_telemetry_rule(RuleName=bad_name, Rule=bad_rule)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    prefix = (
        "1 validation error detected: Value 'AWS::TotallyBogus::NotAResource' at "
        "'rule.resourceType' failed to satisfy constraint: Member must satisfy enum value set: ["
    )
    assert message.startswith(prefix) and message.endswith("]"), (
        f"expected the enum-constraint refusal {prefix!r}...], got {message!r}"
    )
    assert "AWS::S3::Bucket" in message[len(prefix):], (
        f"expected the enum value set to list AWS::S3::Bucket, got {message!r}"
    )

    not_found_code, not_found_message = _client_error(
        lambda: client.get_telemetry_rule(RuleIdentifier=bad_name)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for never-created {bad_name!r}, got {not_found_code!r}"
    )
    assert not_found_message == "Rule not found.", (
        f"expected the not-found message 'Rule not found.', got {not_found_message!r}"
    )

    good_name = ctx.unique_name("sim2real-oa-goodtype-")
    good_rule = {"ResourceType": "AWS::Bedrock::KnowledgeBase", "TelemetryType": "Logs"}
    created = client.create_telemetry_rule(RuleName=good_name, Rule=good_rule)
    rule_arn = created["RuleArn"]
    ctx.on_cleanup(lambda: _delete_ignore_not_found(client, rule_arn))

    # terminal read: independent of the mutating create call
    got = client.get_telemetry_rule(RuleIdentifier=rule_arn)
    assert got["RuleName"] == good_name, f"expected {good_name!r}, got {got.get('RuleName')!r}"
    assert got["TelemetryRule"]["ResourceType"] == "AWS::Bedrock::KnowledgeBase", (
        f"expected ResourceType AWS::Bedrock::KnowledgeBase, got {got['TelemetryRule'].get('ResourceType')!r}"
    )


def _ensure_telemetry_evaluation(client, region, timeout_s=300.0, interval_s=5.0):
    status = client.get_telemetry_evaluation_status().get("Status")
    if status == "RUNNING":
        return
    if status in (None, "NOT_STARTED", "STOPPED", "FAILED_START", "FAILED_STOP"):
        try:
            # Regions must not name the current region: it is always implicit.
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
                f"telemetry evaluation failed to start: FailureReason={resp.get('FailureReason')!r}"
            )
        time.sleep(interval_s)
    raise AssertionError(f"telemetry evaluation never reached RUNNING (last={status})")


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
