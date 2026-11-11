"""update-findings-record-state-archive-has-no-effect."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "update-findings-record-state-archive-has-no-effect"
GROUP = "overly-permissive"
SERVICES = ["securityhub"]


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:securityhub")
def run(ctx) -> None:
    """The deprecated UpdateFindings with RecordState ARCHIVED is accepted but leaves the finding
    ACTIVE throughout a 30 s window, while BatchUpdateFindings on the same finding sets workflow
    NOTIFIED and its note, with RecordState still ACTIVE."""
    sh = ctx.client("securityhub")
    _ensure_hub_enabled(sh)
    account_id = _account_id(ctx)
    product_arn = _default_product_arn(ctx, account_id)
    finding_id = ctx.unique_name("sim2real-arch-")
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
    assert landed["RecordState"] == "ACTIVE", f"expected freshly-imported finding ACTIVE, got {landed['RecordState']!r}"

    note_text = ctx.unique_name("sim2real-note-")
    # UpdateFindings returns a plain 200 with an empty body -- no UnprocessedFindings/errors to
    # inspect -- so the only way to observe its (lack of) effect is to re-fetch the finding.
    sh.update_findings(
        Filters={"Id": [{"Value": finding_id, "Comparison": "EQUALS"}]},
        RecordState="ARCHIVED",
        Note={"Text": note_text, "UpdatedBy": "sim2real-behavioral"},
    )

    # Sample repeatedly over a window: the deprecated call must never actually flip RecordState.
    deadline = time.monotonic() + 30
    seen_states = set()
    while time.monotonic() < deadline:
        current = _first_or_none(sh, finding_id)
        if current is not None:
            seen_states.add(current["RecordState"])
        time.sleep(5)
    assert seen_states == {"ACTIVE"}, f"deprecated UpdateFindings changed RecordState: observed {seen_states}"

    # Positive control: the still-supported BatchUpdateFindings Workflow/Note path on the very
    # same finding DOES take effect, proving the finding itself is live and mutable.
    sh.batch_update_findings(
        FindingIdentifiers=[identifier], Workflow={"Status": "NOTIFIED"}, Note={"Text": note_text, "UpdatedBy": "sim2real-behavioral"}
    )
    updated = _poll_until(
        lambda: _first_or_none(sh, finding_id),
        lambda f: f is not None and f["Workflow"]["Status"] == "NOTIFIED",
        timeout_s=300,
        interval_s=5,
    )
    assert updated["Note"]["Text"] == note_text, f"expected note {note_text!r} from BatchUpdateFindings, got {updated['Note'].get('Text')!r}"
    assert updated["RecordState"] == "ACTIVE", f"expected RecordState still ACTIVE after BatchUpdateFindings, got {updated['RecordState']!r}"


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

