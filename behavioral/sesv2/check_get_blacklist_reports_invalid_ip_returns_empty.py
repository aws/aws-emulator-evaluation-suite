"""get-blacklist-reports-invalid-ip-returns-empty."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-blacklist-reports-invalid-ip-returns-empty"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:happy-path", "cap:unclassified", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The IP block-list report operation validates neither IP syntax nor ownership of the requested
    item names: a non-IP string and an unowned well-formed IP both succeed with no report entry."""
    ses = ctx.client("sesv2")

    malformed_result = ses.get_blacklist_reports(BlacklistItemNames=["not-an-ip-address"])
    malformed_report = malformed_result["BlacklistReport"]
    malformed_entry = malformed_report.get("not-an-ip-address")
    assert malformed_entry in (None, []), (
        "expected no blacklist entries for a malformed, non-IP item name, "
        f"got {malformed_entry!r}"
    )

    wellformed_but_unowned_result = ses.get_blacklist_reports(BlacklistItemNames=["192.0.2.1"])
    unowned_report = wellformed_but_unowned_result["BlacklistReport"]
    unowned_entry = unowned_report.get("192.0.2.1")
    assert unowned_entry in (None, []), (
        "expected no blacklist entries for a syntactically valid IP this account does not own, "
        f"got {unowned_entry!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
