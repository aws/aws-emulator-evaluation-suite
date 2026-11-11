"""get-findings-batch-size-limit-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-findings-batch-size-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["macie2"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:macie")
def run(ctx) -> None:
    """GetFindings rejects a findingIds array of more than 50 identifiers; a valid single-id call succeeds."""
    _ensure_macie_enabled(ctx)
    macie = ctx.client("macie2")
    macie.create_sample_findings()

    criteria = {"criterion": {"sample": {"eq": ["true"]}}}
    finding_ids = _poll_until(
        lambda: macie.list_findings(findingCriteria=criteria).get("findingIds", []),
        lambda ids: len(ids) > 0,
        timeout_s=90,
        interval_s=3,
    )

    too_many = [f"{i:032x}" for i in range(51)]
    error = _rejected_error(lambda: macie.get_findings(findingIds=too_many))
    assert error["Code"] == "ValidationException", (
        f"expected ValidationException for 51 findingIds (limit is 50), got {error['Code']!r}"
    )
    assert error["Message"] == (
        f"1 validation error detected: Value '[{', '.join(too_many)}]' at 'findingIds' failed to "
        "satisfy constraint: Member must have length less than or equal to 50"
    ), f"unexpected message: {error['Message']!r}"

    # Positive control: a request within the limit, using a real finding id, succeeds.
    result = macie.get_findings(findingIds=finding_ids[:1])
    assert len(result["findings"]) == 1, (
        f"expected exactly 1 finding for a single-id GetFindings, got {len(result['findings'])}"
    )
    assert result["findings"][0]["id"] == finding_ids[0], (
        f"expected returned finding id {finding_ids[0]!r}, got {result['findings'][0]['id']!r}"
    )


def _rejected_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a target
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _ensure_macie_enabled(ctx) -> None:
    from botocore.exceptions import ClientError

    macie = ctx.client("macie2")
    try:
        macie.get_macie_session()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code not in ("ResourceNotFoundException", "AccessDeniedException"):
            raise
        try:
            macie.enable_macie()
        except ClientError as exc2:
            if exc2.response["Error"]["Code"] != "ConflictException":
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
