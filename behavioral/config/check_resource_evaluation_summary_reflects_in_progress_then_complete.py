"""resource-evaluation-summary-reflects-in-progress-then-complete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "resource-evaluation-summary-reflects-in-progress-then-complete"
GROUP = "data-plane"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PROACTIVE StartResourceEvaluation's GetResourceEvaluationSummary reads IN_PROGRESS until it
    reaches SUCCEEDED (NOT_APPLICABLE) or FAILED (with a reason), echoing the EvaluationMode and
    resource details supplied on the call."""
    config = ctx.client("config")
    proactive_s3 = _proactive_rules_for(config, "AWS::S3::Bucket")
    assert proactive_s3 == [], (
        f"precondition: no PROACTIVE rule may scope AWS::S3::Bucket, found {proactive_s3!r}"
    )

    resource_id = ctx.unique_name("sim2real-eval-")
    resource_type = "AWS::S3::Bucket"
    resource_config = json.dumps(
        {
            "BucketName": resource_id,
            "VersioningConfiguration": {"Status": "Enabled"},
        }
    )

    started = config.start_resource_evaluation(
        ResourceDetails={
            "ResourceId": resource_id,
            "ResourceType": resource_type,
            "ResourceConfiguration": resource_config,
            "ResourceConfigurationSchemaType": "CFN_RESOURCE_SCHEMA",
        },
        EvaluationMode="PROACTIVE",
    )
    evaluation_id = started["ResourceEvaluationId"]

    statuses_seen = []

    def _probe():
        summary = config.get_resource_evaluation_summary(
            ResourceEvaluationId=evaluation_id
        )
        statuses_seen.append(summary["EvaluationStatus"]["Status"])
        return summary

    terminal = _poll_until(
        _probe,
        lambda s: s["EvaluationStatus"]["Status"] in ("SUCCEEDED", "FAILED"),
        timeout_s=90,
        interval_s=2,
    )

    assert terminal is not None, f"never reached terminal status, saw {statuses_seen}"
    # A fast PROACTIVE evaluation can be terminal on the first read; every earlier read is
    # the one non-terminal status, IN_PROGRESS.
    assert all(st == "IN_PROGRESS" for st in statuses_seen[:-1]), (
        f"every read before the terminal status must be IN_PROGRESS; saw {statuses_seen}"
    )
    assert terminal["EvaluationMode"] == "PROACTIVE"
    assert terminal["ResourceDetails"]["ResourceId"] == resource_id
    assert terminal["ResourceDetails"]["ResourceType"] == resource_type

    status = terminal["EvaluationStatus"]["Status"]
    if status == "SUCCEEDED":
        # The precondition above holds no PROACTIVE rule for AWS::S3::Bucket, so a
        # successful evaluation's compliance is deterministically NOT_APPLICABLE.
        assert terminal["Compliance"] == "NOT_APPLICABLE", (
            f"a SUCCEEDED evaluation with no PROACTIVE rule for the resource type must "
            f"report Compliance NOT_APPLICABLE, got {terminal.get('Compliance')!r}"
        )
    else:
        assert terminal["EvaluationStatus"].get("FailureReason"), (
            "a FAILED evaluation must carry a concrete, non-empty FailureReason, not a "
            "silent failure"
        )


def _proactive_rules_for(config, resource_type):
    """Names of the account's PROACTIVE-mode rules whose scope can cover resource_type."""
    found = []
    for page in config.get_paginator("describe_config_rules").paginate():
        for rule in page["ConfigRules"]:
            modes = {m.get("Mode") for m in rule.get("EvaluationModes", [])}
            types = rule.get("Scope", {}).get("ComplianceResourceTypes") or [resource_type]
            if "PROACTIVE" in modes and resource_type in types:
                found.append(rule["ConfigRuleName"])
    return found


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last if last is not None and predicate(last) else None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
