"""batch-import-findings-customer-fields-preserved-on-reimport."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "batch-import-findings-customer-fields-preserved-on-reimport"
GROUP = "state"
SERVICES = ["securityhub"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:securityhub")
def run(ctx) -> None:
    """Re-importing a finding updates provider fields but does not clobber customer-set Workflow/Note."""
    sh = ctx.client("securityhub")
    _ensure_hub_enabled(sh)
    account_id = _account_id(ctx)
    product_arn = _default_product_arn(ctx, account_id)
    finding_id = ctx.unique_name("sim2real-reimport-")
    title = ctx.unique_name("sim2real-title-")

    finding_v1 = _make_finding(account_id, product_arn, finding_id, title, Description="sim2real v1 description")
    sh.batch_import_findings(Findings=[finding_v1])
    identifier = {"Id": finding_id, "ProductArn": product_arn}
    ctx.on_cleanup(lambda: sh.batch_update_findings(FindingIdentifiers=[identifier], Workflow={"Status": "RESOLVED"}))

    _poll_until(
        lambda: sh.get_findings(Filters={"Id": [{"Value": finding_id, "Comparison": "EQUALS"}]})["Findings"],
        lambda fs: len(fs) == 1,
        timeout_s=300,
        interval_s=5,
    )

    note_text = ctx.unique_name("sim2real-note-")
    sh.batch_update_findings(
        FindingIdentifiers=[identifier],
        Workflow={"Status": "NOTIFIED"},
        Note={"Text": note_text, "UpdatedBy": "sim2real-behavioral"},
    )
    # GetFindings takes far longer to reflect a BatchUpdateFindings write than the initial
    # BatchImportFindings ingest (up to ~300 s on AWS), so a 180 s window is too short.
    _poll_until(
        lambda: _first_or_none(sh, finding_id),
        lambda f: f is not None and f["Workflow"]["Status"] == "NOTIFIED",
        timeout_s=400,
        interval_s=5,
    )

    # The finding provider re-imports the same finding (Id+ProductArn) with a changed
    # Description but no knowledge of the customer's Workflow/Note edits.
    finding_v2 = _make_finding(account_id, product_arn, finding_id, title, Description="sim2real v2 description")
    resp2 = sh.batch_import_findings(Findings=[finding_v2])
    assert resp2["FailedCount"] == 0, resp2

    updated = _poll_until(
        lambda: _first_or_none(sh, finding_id),
        lambda f: f is not None and f["Description"] == "sim2real v2 description",
        timeout_s=400,
        interval_s=5,
    )
    assert updated["Workflow"]["Status"] == "NOTIFIED", updated.get("Workflow")
    assert updated["Note"]["Text"] == note_text, updated.get("Note")


# ===== helpers =====
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
