"""op-contract-getCredentialReport."""
from __future__ import annotations

import base64
import csv
import io
import time
from typing import Any

from behavioral_harness import tags

CHECK = "op-contract-getCredentialReport"
GROUP = "error-semantics"
SERVICES = ["iam"]


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCredentialReport returns a text/csv report with a GeneratedTime whose
    <root_account> row carries this account's root ARN, which a static report
    could not know."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    _generate_report_tolerating_limit(iam)
    report: dict[str, Any] = _poll_for_report(iam, timeout_s=_budget_s(ctx, 90.0))

    report_format = report["ReportFormat"]
    assert report_format == "text/csv", f"expected ReportFormat text/csv, got {report_format!r}"
    generated_time = report["GeneratedTime"]
    assert generated_time is not None, "credential report response is missing GeneratedTime"

    # botocore blob members are already base64-decoded into raw bytes by
    # the time they reach the response dict -- decode straight to text.
    # Fall back to an explicit base64 decode only if a future/alternate
    # botocore version hands back the still-encoded string form.
    content = report["Content"]
    csv_text = (
        content.decode("utf-8")
        if isinstance(content, bytes)
        else base64.b64decode(content).decode("utf-8")
    )
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    assert rows, "credential report has no rows at all"

    root_rows = [row for row in rows if row["user"] == "<root_account>"]
    assert root_rows, "credential report is missing its '<root_account>' row"
    root_row = root_rows[0]
    expected_root_arn = f"arn:aws:iam::{account_id}:root"
    assert root_row["arn"] == expected_root_arn, (
        f"root row arn {root_row['arn']!r} does not match this account's real "
        f"root arn {expected_root_arn!r} -- report does not reflect live account state"
    )


def _generate_report_tolerating_limit(iam) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            iam.generate_credential_report()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            # LimitExceeded answers while another generation is still running: retry it only.
            if code != "LimitExceeded":
                raise
            time.sleep(2.0)
    raise AssertionError("generate_credential_report kept returning LimitExceeded")


def _poll_for_report(iam, timeout_s: float) -> dict[str, Any]:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return iam.get_credential_report()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            # ReportInProgress answers until the generated report is ready: retry it only.
            if code != "ReportInProgress":
                raise
            time.sleep(2.0)
    raise AssertionError(f"credential report never became available within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
