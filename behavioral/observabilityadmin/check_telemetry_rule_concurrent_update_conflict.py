"""telemetry-rule-concurrent-update-conflict."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "telemetry-rule-concurrent-update-conflict"
GROUP = "concurrency"
SERVICES = ["observabilityadmin"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:observabilityadmin-telemetry-evaluation")
def run(ctx) -> None:
    """Concurrent UpdateTelemetryRule calls on one rule each succeed or fail with ConflictException, at
    least one succeeds, and the final RetentionInDays is one value a successful caller submitted."""
    client = ctx.client("observabilityadmin")
    _ensure_telemetry_evaluation(ctx, client)
    name = ctx.unique_name("sim2real-oa-race-")

    base_rule = {
        "ResourceType": "AWS::Bedrock::KnowledgeBase",
        "TelemetryType": "Logs",
        "DestinationConfiguration": {
            "DestinationType": "cloud-watch-logs",
            "RetentionInDays": 1,
            "LogDeliveryParameters": {"LogTypes": ["APPLICATION_LOGS"]},
        },
    }
    created = client.create_telemetry_rule(
        RuleName=name, Rule=base_rule, Tags={"sim2real": CHECK}
    )
    rule_arn = created["RuleArn"]
    ctx.on_cleanup(lambda: _delete_ignore_not_found(client, rule_arn))

    n_racers = 8
    # Only valid CloudWatch Logs retention periods: 10 is documented as invalid and
    # would fail every racer that draws it with ValidationException, unrelated to the
    # concurrency this check exists to exercise.
    candidate_values = [3, 5, 7, 14, 30, 60, 90, 120][:n_racers]

    def _update(retention: int):
        rule = {
            "ResourceType": "AWS::Bedrock::KnowledgeBase",
            "TelemetryType": "Logs",
            "DestinationConfiguration": {
                "DestinationType": "cloud-watch-logs",
                "RetentionInDays": retention,
                "LogDeliveryParameters": {"LogTypes": ["APPLICATION_LOGS"]},
            },
        }
        try:
            client.update_telemetry_rule(RuleIdentifier=rule_arn, Rule=rule)
            return (retention, True, None)
        except ClientError as e:
            return (retention, False, e.response["Error"]["Code"], e.response["Error"].get("Message"))

    results = []
    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        futures = [pool.submit(_update, v) for v in candidate_values]
        for fut in as_completed(futures):
            results.append(fut.result())

    successes = [r for r in results if r[1]]
    failures = [r for r in results if not r[1]]

    assert len(successes) >= 1, f"expected at least one racer to succeed, got {results}"
    # Only the code is graded: AWS often accepts every concurrent update, and documents no
    # ConflictException message for this operation.
    for _, _, code, message in failures:
        assert code == "ConflictException", f"unexpected failure code: {code} ({message})"

    final_retention = client.get_telemetry_rule(RuleIdentifier=rule_arn)["TelemetryRule"][
        "DestinationConfiguration"
    ]["RetentionInDays"]
    success_values = {r[0] for r in successes}
    assert final_retention in success_values, (
        f"final RetentionInDays={final_retention} is not among the values a successful "
        f"racer submitted ({success_values}); the rule's state may have been corrupted"
    )


def _ensure_telemetry_evaluation(ctx, client, timeout_s=300.0, interval_s=5.0):
    status = client.get_telemetry_evaluation_status().get("Status")
    if status == "RUNNING":
        return
    # Telemetry evaluation is an account setting: one this check starts is stopped again.
    ctx.on_cleanup(lambda: _stop_telemetry_evaluation(client))
    if status in (None, "NOT_STARTED", "STOPPED", "FAILED_START", "FAILED_STOP"):
        try:
            # The current region is always implicit; passing it in `Regions` is
            # documented as invalid and drives the account into FAILED_START.
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


def _delete_ignore_not_found(client, rule_arn: str) -> None:
    try:
        client.delete_telemetry_rule(RuleIdentifier=rule_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
