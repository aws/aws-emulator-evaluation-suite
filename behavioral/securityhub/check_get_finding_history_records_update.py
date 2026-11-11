"""get-finding-history-records-update."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "get-finding-history-records-update"
GROUP = "telemetry"
SERVICES = ["securityhub"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:securityhub")
def run(ctx) -> None:
    """GetFindingHistory records a Note update made via BatchUpdateFindings as an observable audit event,
    attributed to the caller that made the call and carrying no prior value for a note set for the first
    time."""
    sh = ctx.client("securityhub")
    _ensure_hub_enabled(sh)
    identity = ctx.client("sts").get_caller_identity()
    account_id, caller_arn = identity["Account"], identity["Arn"]
    product_arn = _default_product_arn(ctx, account_id)
    finding_id = ctx.unique_name("sim2real-hist-")
    finding = _make_finding(account_id, product_arn, finding_id, ctx.unique_name("sim2real-title-"))
    sh.batch_import_findings(Findings=[finding])
    identifier = {"Id": finding_id, "ProductArn": product_arn}
    ctx.on_cleanup(lambda: sh.batch_update_findings(FindingIdentifiers=[identifier], Workflow={"Status": "RESOLVED"}))

    _poll_until(
        lambda: sh.get_findings(Filters={"Id": [{"Value": finding_id, "Comparison": "EQUALS"}]})["Findings"],
        lambda fs: len(fs) == 1,
    )

    note_text = ctx.unique_name("sim2real-hist-note-")
    sh.batch_update_findings(
        FindingIdentifiers=[identifier], Note={"Text": note_text, "UpdatedBy": "sim2real-behavioral"}
    )

    def _note_update_matches():
        records = sh.get_finding_history(FindingIdentifier=identifier)["Records"]
        matches = []
        for record in records:
            for update in record.get("Updates", []):
                if update.get("UpdatedField") == "Note" and note_text in str(update.get("NewValue", "")):
                    matches.append((record, update))
        return matches

    matches = _poll_until(_note_update_matches, lambda ms: len(ms) >= 1, timeout_s=90, interval_s=5)
    assert len(matches) == 1, (
        f"expected exactly one Note-update history record naming {note_text!r}, got {len(matches)}: {matches!r}"
    )
    record, update = matches[0]

    assert record["FindingIdentifier"] == identifier, (
        f"history record is for the wrong finding: expected {identifier!r}, got {record['FindingIdentifier']!r}"
    )
    assert record["UpdateSource"]["Type"] == "BATCH_UPDATE_FINDINGS", (
        f"expected UpdateSource.Type 'BATCH_UPDATE_FINDINGS', got {record['UpdateSource']!r}"
    )
    assert record["UpdateSource"]["Identity"] == caller_arn, (
        f"expected the update attributed to caller {caller_arn!r}, got {record['UpdateSource'].get('Identity')!r}"
    )
    assert "OldValue" not in update, (
        f"a Note set for the first time must carry no OldValue, got {update.get('OldValue')!r}"
    )
    new_value = json.loads(update["NewValue"])
    assert new_value["Text"] == note_text, f"expected Note.Text {note_text!r}, got {new_value!r}"
    assert new_value["UpdatedBy"] == "sim2real-behavioral", (
        f"expected Note.UpdatedBy 'sim2real-behavioral', got {new_value!r}"
    )


def _ensure_hub_enabled(sh):
    from botocore.exceptions import ClientError

    try:
        sh.enable_security_hub(EnableDefaultStandards=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceConflictException":
            raise


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
