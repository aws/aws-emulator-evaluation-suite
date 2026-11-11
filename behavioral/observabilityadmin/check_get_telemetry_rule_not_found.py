"""get-telemetry-rule-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-telemetry-rule-not-found"
GROUP = "error-semantics"
SERVICES = ["observabilityadmin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:observabilityadmin-telemetry-evaluation")
def run(ctx) -> None:
    """With telemetry evaluation RUNNING, GetTelemetryRule on a well-formed nonexistent RuleIdentifier
    fails with ResourceNotFoundException "Rule not found.", while GetTelemetryRule on a rule the
    check created returns its RuleArn."""
    client = ctx.client("observabilityadmin")
    _ensure_telemetry_evaluation(ctx, client)

    real_arn = _create_probe_rule(ctx, client)
    positive = client.get_telemetry_rule(RuleIdentifier=real_arn)
    assert positive["RuleArn"] == real_arn, (
        f"positive control: expected GetTelemetryRule({real_arn!r}) to succeed and echo "
        f"the same ARN, got {positive.get('RuleArn')!r}"
    )

    bogus_identifier = ctx.unique_name("sim2real-oa-notfound-")
    code, message = _client_error(
        lambda: client.get_telemetry_rule(RuleIdentifier=bogus_identifier)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a well-formed but never-created "
        f"RuleIdentifier {bogus_identifier!r}, got {code!r}"
    )
    assert message == "Rule not found.", (
        f"expected the not-found message 'Rule not found.', got {message!r}"
    )


def _ensure_telemetry_evaluation(ctx, client, timeout_s=300.0, interval_s=5.0):
    status = client.get_telemetry_evaluation_status().get("Status")
    if status == "RUNNING":
        return
    _ensure_telemetry_enablement_slr(ctx)

    last_failure = None
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if status in (None, "NOT_STARTED", "STOPPED", "FAILED_START", "FAILED_STOP"):
            try:
                client.start_telemetry_evaluation()
            except ClientError as e:
                if e.response["Error"]["Code"] != "ConflictException":
                    raise
        time.sleep(interval_s)
        resp = client.get_telemetry_evaluation_status()
        status = resp.get("Status")
        if status == "RUNNING":
            return
        if status == "FAILED_START":
            # SLR_UNAVAILABLE here means the service-linked role IAM just created (or
            # confirmed already exists) has not yet propagated to ObservabilityAdmin's
            # own view -- retrying StartTelemetryEvaluation is what clears it, a single
            # attempt is not enough on a cold account.
            last_failure = resp.get("FailureReason")
            continue
    raise AssertionError(
        f"telemetry evaluation never reached RUNNING within {timeout_s}s "
        f"(last_status={status!r}, last_failure_reason={last_failure!r})"
    )


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


def _create_probe_rule(ctx, client) -> str:
    """A minimal telemetry rule that exists solely to prove GetTelemetryRule succeeds on a
    real identifier (the positive control the not-found probe needs)."""
    name = ctx.unique_name("sim2real-oa-notfound-probe-")
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
        RuleName=name, Rule=rule, Tags={"sim2real-check": CHECK}
    )
    rule_arn = created["RuleArn"]
    ctx.on_cleanup(lambda: _delete_ignore_not_found(client, rule_arn))
    return rule_arn


def _delete_ignore_not_found(client, rule_arn: str) -> None:
    try:
        client.delete_telemetry_rule(RuleIdentifier=rule_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
