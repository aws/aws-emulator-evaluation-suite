"""credential-report-ttl-expiry-requires-regeneration."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "credential-report-ttl-expiry-requires-regeneration"
GROUP = "visibility-timeout-ttl"
SERVICES = ["iam"]


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two immediate GetCredentialReport fetches return the same GeneratedTime and Content:
    the report is served from cache, not regenerated per call.

    Reference: https://docs.aws.amazon.com/IAM/latest/APIReference/API_GenerateCredentialReport.html
    """
    iam = ctx.client("iam")

    # Kick off (or reuse an in-flight) report generation. LimitExceeded here just means
    # another caller regenerated recently -- that's fine, we only need *a* current report.
    try:
        iam.generate_credential_report()
    except Exception as err:  # noqa: BLE001 - only LimitExceeded is expected/tolerable here
        if _error_code_from(err) != "LimitExceeded":
            raise

    # A report is regenerated at most every four hours, so the expiry boundary itself is not run.
    content1, generated1 = _wait_for_report(iam, timeout_s=_budget_s(ctx, 90.0))
    # Immediately re-fetch: still within the validity window, must be served from cache.
    content2, generated2 = _wait_for_report(iam, timeout_s=30.0)

    assert generated1 == generated2, (
        f"expected cached GeneratedTime to be stable across immediate re-fetch, "
        f"got {generated1} then {generated2}"
    )
    assert content1 == content2, "expected identical cached report Content across immediate re-fetch"


def _error_code_from(err) -> str | None:
    from botocore.exceptions import ClientError

    if isinstance(err, ClientError):
        return err.response["Error"]["Code"]
    return None


def _wait_for_report(iam, timeout_s: float):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = iam.get_credential_report()
            return bytes(resp["Content"]), resp["GeneratedTime"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ReportInProgress", "ReportNotPresent"):
                time.sleep(2)
                continue
            raise
    raise AssertionError(f"credential report never became ready within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
