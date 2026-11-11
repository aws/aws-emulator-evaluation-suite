"""sample-findings-generation-and-retrieval."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "sample-findings-generation-and-retrieval"
GROUP = "data-plane"
SERVICES = ["macie2"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:macie")
def run(ctx) -> None:
    """CreateSampleFindings populates retrievable findings flagged sample=true, not archived,
    each carrying the category its own type prefix implies (Policy:* -> POLICY,
    SensitiveData:* -> CLASSIFICATION)."""
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

    requested = finding_ids[:10]
    findings = macie.get_findings(findingIds=requested)["findings"]
    assert len(findings) == len(requested), (
        f"expected {len(requested)} findings for requested ids, got {len(findings)}"
    )
    for finding in findings:
        assert finding["sample"] is True, f"expected sample=True, got {finding['sample']!r} for {finding['id']}"
        assert finding["archived"] is False, (
            f"expected archived=False, got {finding['archived']!r} for {finding['id']}"
        )
        ftype = finding["type"]
        category = finding["category"]
        if ftype.startswith("Policy:"):
            expected_category = "POLICY"
        elif ftype.startswith("SensitiveData:"):
            expected_category = "CLASSIFICATION"
        else:
            raise AssertionError(f"unrecognized sample finding type {ftype!r} for {finding['id']}")
        assert category == expected_category, (
            f"type {ftype!r} implies category {expected_category!r}, got {category!r} for {finding['id']}"
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
    """Enable Macie when the account has no session, and disable it again at cleanup so the
    account-wide setting ends in the state it started in."""
    from botocore.exceptions import ClientError

    macie = ctx.client("macie2")
    try:
        macie.get_macie_session()
        return
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code not in ("ResourceNotFoundException", "AccessDeniedException"):
            raise
    try:
        macie.enable_macie()
    except ClientError as exc2:
        if exc2.response["Error"]["Code"] != "ConflictException":
            raise
        return
    ctx.on_cleanup(macie.disable_macie)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
