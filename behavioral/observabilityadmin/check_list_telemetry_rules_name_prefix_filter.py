"""list-telemetry-rules-name-prefix-filter."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-telemetry-rules-name-prefix-filter"
GROUP = "data-plane"
SERVICES = ["observabilityadmin"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:observabilityadmin-telemetry-evaluation")
def run(ctx) -> None:
    """ListTelemetryRules with RuleNamePrefix returns rules whose name matches the prefix
    and excludes them when queried with an unrelated prefix -- the filter is actually
    applied server-side, not ignored."""
    client = ctx.client("observabilityadmin")
    _ensure_telemetry_evaluation(client)
    prefix = ctx.unique_name("sim2real-oa-listpfx-")
    name = f"{prefix}-target"

    created = client.create_telemetry_rule(
        RuleName=name,
        Rule={"ResourceType": "AWS::Bedrock::KnowledgeBase", "TelemetryType": "Logs"},
    )
    rule_arn = created["RuleArn"]
    ctx.on_cleanup(lambda: _delete_ignore_not_found(client, rule_arn))

    matches = _collect_names(client, RuleNamePrefix=prefix)
    assert name in matches, f"expected {name!r} in matching-prefix listing, got {matches!r}"

    other_prefix = "sim2real-oa-zzz-should-never-match-anything"
    non_matches = _collect_names(client, RuleNamePrefix=other_prefix)
    assert name not in non_matches, (
        f"expected {name!r} absent under unrelated prefix, got {non_matches!r}"
    )


def _ensure_telemetry_evaluation(client, timeout_s=300.0, interval_s=5.0):
    status = client.get_telemetry_evaluation_status().get("Status")
    if status == "RUNNING":
        return
    if status in (None, "NOT_STARTED", "STOPPED", "FAILED_START", "FAILED_STOP"):
        try:
            # The current region is always implicit and must never be named in
            # Regions -- doing so drives the account into FAILED_START.
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


def _collect_names(client, **kwargs):
    names = []
    next_token = None
    while True:
        params = dict(kwargs)
        if next_token:
            params["NextToken"] = next_token
        resp = client.list_telemetry_rules(**params)
        names.extend(s["RuleName"] for s in resp.get("TelemetryRuleSummaries", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return names


def _delete_ignore_not_found(client, rule_arn: str) -> None:
    try:
        client.delete_telemetry_rule(RuleIdentifier=rule_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
