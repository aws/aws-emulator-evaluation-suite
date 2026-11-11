"""batch-update-findings-workflow-status-transition."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "batch-update-findings-workflow-status-transition"
GROUP = "state"
SERVICES = ["securityhub"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:securityhub")
def run(ctx) -> None:
    """BatchUpdateFindings drives Workflow.Status NEW->NOTIFIED->RESOLVED and persists VerificationState."""
    sh = ctx.client("securityhub")
    _ensure_hub_enabled(sh)
    account_id = _account_id(ctx)
    product_arn = _default_product_arn(ctx, account_id)
    finding_id = ctx.unique_name("sim2real-wf-")
    finding = _make_finding(account_id, product_arn, finding_id, ctx.unique_name("sim2real-title-"))
    sh.batch_import_findings(Findings=[finding])
    identifier = {"Id": finding_id, "ProductArn": product_arn}
    ctx.on_cleanup(lambda: sh.batch_update_findings(FindingIdentifiers=[identifier], Workflow={"Status": "RESOLVED"}))

    landed = _poll_until(
        lambda: sh.get_findings(Filters={"Id": [{"Value": finding_id, "Comparison": "EQUALS"}]})["Findings"],
        lambda fs: len(fs) == 1,
        timeout_s=300,
        interval_s=5,
    )[0]
    assert landed["Workflow"]["Status"] == "NEW", f"expected freshly-imported finding Workflow.Status NEW, got {landed['Workflow']['Status']!r}"

    resp = sh.batch_update_findings(FindingIdentifiers=[identifier], Workflow={"Status": "NOTIFIED"})
    assert resp["UnprocessedFindings"] == [], f"expected no UnprocessedFindings for {identifier}, got {resp['UnprocessedFindings']!r}"
    status = _poll_until(
        lambda: _first_or_none(sh, finding_id),
        lambda f: f is not None and f["Workflow"]["Status"] == "NOTIFIED",
        timeout_s=300,
        interval_s=5,
    )["Workflow"]["Status"]
    assert status == "NOTIFIED", f"expected Workflow.Status NOTIFIED after BatchUpdateFindings, got {status!r}"

    sh.batch_update_findings(
        FindingIdentifiers=[identifier], Workflow={"Status": "RESOLVED"}, VerificationState="TRUE_POSITIVE"
    )
    final = _poll_until(
        lambda: _first_or_none(sh, finding_id),
        lambda f: f is not None and f["Workflow"]["Status"] == "RESOLVED",
        timeout_s=300,
        interval_s=5,
    )
    assert final["VerificationState"] == "TRUE_POSITIVE", f"expected VerificationState TRUE_POSITIVE to persist alongside RESOLVED, got {final['VerificationState']!r}"


def _first_or_none(sh, finding_id):
    findings = sh.get_findings(Filters={"Id": [{"Value": finding_id, "Comparison": "EQUALS"}]})["Findings"]
    return findings[0] if findings else None


def _ensure_hub_enabled(sh):
    from botocore.exceptions import ClientError

    try:
        sh.enable_security_hub(EnableDefaultStandards=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceConflictException":
            raise


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _default_product_arn(ctx, account_id):
    return f"arn:aws:securityhub:{ctx.region}:{account_id}:product/{account_id}/default"


def _now_iso():
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _make_finding(account_id, product_arn, finding_id, title, severity_label="LOW", **overrides):
    now = _now_iso()
    finding = {
        "SchemaVersion": "2018-10-08",
        "Id": finding_id,
        "ProductArn": product_arn,
        "GeneratorId": "sim2real-behavioral-test",
        "AwsAccountId": account_id,
        "Types": ["Software and Configuration Checks/Vulnerabilities/CVE"],
        "CreatedAt": now,
        "UpdatedAt": now,
        "Title": title,
        "Description": "sim2real behavioral fidelity test finding",
        "Severity": {"Label": severity_label},
        "Resources": [{"Type": "Other", "Id": f"sim2real:{finding_id}"}],
    }
    finding.update(overrides)
    return finding


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
