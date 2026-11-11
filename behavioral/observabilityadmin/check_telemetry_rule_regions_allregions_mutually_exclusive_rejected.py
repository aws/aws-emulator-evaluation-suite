"""telemetry-rule-regions-allregions-mutually-exclusive-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "telemetry-rule-regions-allregions-mutually-exclusive-rejected"
GROUP = "overly-permissive"
SERVICES = ["observabilityadmin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:observabilityadmin-telemetry-evaluation")
def run(ctx) -> None:
    """CreateTelemetryRule rejects a Rule that specifies both Regions and AllRegions (they
    are documented as mutually exclusive) with ValidationException, no rule is created, and
    an otherwise-identical Rule using only Regions succeeds (positive control)."""
    client = ctx.client("observabilityadmin")
    _ensure_telemetry_evaluation(client)
    bad_name = ctx.unique_name("sim2real-oa-excl-bad-")

    bad_rule = {
        "ResourceType": "AWS::Bedrock::KnowledgeBase",
        "TelemetryType": "Logs",
        "Regions": [ctx.region],
        "AllRegions": True,
    }
    code, message = _client_error(
        lambda: client.create_telemetry_rule(RuleName=bad_name, Rule=bad_rule)
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a Rule with both Regions and AllRegions set, got {code!r}"
    )
    expected_message = (
        "Parameters 'regions' and 'allRegions' are mutually exclusive. "
        "Provide one or the other, not both."
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # effect absent: nothing was created under that name
    not_found_code, not_found_message = _client_error(
        lambda: client.get_telemetry_rule(RuleIdentifier=bad_name)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"expected the rejected rule name to not exist, got {not_found_code!r}"
    )
    assert not_found_message == "Rule not found.", (
        f"expected the not-found message 'Rule not found.', got {not_found_message!r}"
    )

    # positive control: only Regions set (no AllRegions) succeeds
    good_name = ctx.unique_name("sim2real-oa-excl-good-")
    good_rule = {
        "ResourceType": "AWS::Bedrock::KnowledgeBase",
        "TelemetryType": "Logs",
        "Regions": [ctx.region],
    }
    created = client.create_telemetry_rule(
        RuleName=good_name, Rule=good_rule, Tags={"sim2real": CHECK}
    )
    rule_arn = created["RuleArn"]
    ctx.on_cleanup(lambda: _delete_ignore_not_found(client, rule_arn))

    # terminal read: independent of the CreateTelemetryRule response
    fetched = client.get_telemetry_rule(RuleIdentifier=good_name)
    assert fetched.get("RuleArn") == rule_arn, (
        f"expected GetTelemetryRule to return the created rule {rule_arn!r}, got {fetched.get('RuleArn')!r}"
    )


def _ensure_telemetry_evaluation(client, timeout_s=300.0, interval_s=5.0):
    status = client.get_telemetry_evaluation_status().get("Status")
    if status == "RUNNING":
        return
    if status in (None, "NOT_STARTED", "STOPPED", "FAILED_START", "FAILED_STOP"):
        try:
            # Regions is for opting IN additional spoke regions; the current region is
            # implicit and must not be passed here (StartTelemetryEvaluationInput docs).
            client.start_telemetry_evaluation()
        except ClientError as e:
            if e.response["Error"]["Code"] != "ConflictException":
                raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got = client.get_telemetry_evaluation_status()
        status = got.get("Status")
        if status == "RUNNING":
            return
        if status == "FAILED_START":
            raise AssertionError(
                f"telemetry evaluation failed to start: {got.get('FailureReason')!r}"
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
