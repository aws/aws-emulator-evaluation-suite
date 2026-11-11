"""credential-report-ready-then-expires."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "credential-report-ready-then-expires"
GROUP = "visibility-timeout-ttl"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCredentialReport answers ReportInProgress until generation completes, then text/csv.

    When GenerateCredentialReport already reports COMPLETE, an immediate Get must succeed.
    """
    iam = ctx.client("iam")

    gen = iam.generate_credential_report()
    gen_state = gen.get("State")
    assert gen_state in ("STARTED", "INPROGRESS", "COMPLETE"), (
        f"unexpected State from GenerateCredentialReport: {gen!r}"
    )

    # A report still within its ~4h validity is COMPLETE at once; then Get must not be in progress.
    immediate_code = _error_code(lambda: iam.get_credential_report())
    if gen_state == "COMPLETE":
        assert immediate_code == _SUCCEEDED, (
            f"GenerateCredentialReport reported State=COMPLETE but the immediate "
            f"GetCredentialReport failed with {immediate_code!r}"
        )
    elif immediate_code != _SUCCEEDED:
        assert immediate_code == "ReportInProgress", (
            f"expected ReportInProgress while State={gen_state!r}, got {immediate_code!r}"
        )

    content = None
    report_format = None
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        try:
            resp = iam.get_credential_report()
            content = resp["Content"]
            report_format = resp["ReportFormat"]
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            assert code == "ReportInProgress", f"unexpected error while polling: {code}"
            time.sleep(3.0)

    assert content is not None, "credential report never reached COMPLETE within poll window"
    assert report_format == "text/csv", f"expected text/csv, got {report_format!r}"
    # `Content` is a blob field; botocore already base64-decodes it into raw bytes, so no
    # further base64 decoding is needed (doing so raises a padding error).
    csv_text = content.decode("utf-8") if isinstance(content, bytes) else content
    header = csv_text.splitlines()[0]
    assert header.startswith("user,arn,user_creation_time"), f"unexpected CSV header: {header!r}"
    assert "password_enabled" in header, f"expected password_enabled column in header: {header!r}"


_SUCCEEDED = "<call succeeded>"


def _error_code(fn):
    """The ClientError code, or the truthy ``_SUCCEEDED`` sentinel that no error code can equal."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    return _SUCCEEDED


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
