"""start-cis-session-unauthorized-scan-job-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "start-cis-session-unauthorized-scan-job-rejected"
GROUP = "overly-permissive"
SERVICES = ["inspector2"]

_IDENTITY_REFUSAL = "Identity user principal does not contain valid resourceId"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartCisSession and StopCisSession from an ordinary IAM caller both fail with
    ValidationException and the identical exact message, while ListUsageTotals succeeds for the same
    identity."""
    inspector2 = ctx.client("inspector2")
    bogus_scan_job_id = str(uuid.uuid4())

    # Positive control: Inspector2 read APIs are otherwise fully functional for this caller
    # (avoid depending on EC2/CIS-specific enablement, which this check intentionally never sets up).
    resp = inspector2.list_usage_totals()
    assert "totals" in resp, f"expected a usage-totals response, got {resp!r}"

    err = _client_error(
        lambda: inspector2.start_cis_session(
            scanJobId=bogus_scan_job_id, message={"sessionToken": str(uuid.uuid4())}
        )
    )
    assert err.get("Code") == "ValidationException", (
        f"expected StartCisSession to reject a non-SSM-plugin caller with ValidationException, "
        f"got {err.get('Code')!r}"
    )
    assert err.get("Message") == _IDENTITY_REFUSAL, (
        f"expected the identity/resourceId gate in the message, got {err.get('Message')!r}"
    )

    # Effect absent: no session was actually started, so ending it fails the identical way.
    stop_err = _client_error(
        lambda: inspector2.stop_cis_session(
            scanJobId=bogus_scan_job_id,
            sessionToken=str(uuid.uuid4()),
            message={"status": "SUCCESS", "progress": {"totalChecks": 0}},
        )
    )
    assert stop_err.get("Code") == "ValidationException", (
        f"expected the never-started session to remain unusable with ValidationException, "
        f"got {stop_err.get('Code')!r}"
    )
    assert stop_err.get("Message") == _IDENTITY_REFUSAL, (
        f"expected the identity/resourceId gate in the message, got {stop_err.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected real AWS to reject this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
