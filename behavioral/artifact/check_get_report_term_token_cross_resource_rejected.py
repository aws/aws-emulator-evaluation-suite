"""get-report-term-token-cross-resource-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-report-term-token-cross-resource-rejected"
GROUP = "overly-permissive"
SERVICES = ["artifact"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetReport pairing report A with a termToken minted for a report under a different term fails
    ValidationException "The provided token is invalid.", while (A, A's token) succeeds."""
    art = ctx.client("artifact")

    def _is_open(r):
        # ListReports' ReportSummary does not surface uploadState on real AWS (observed
        # None on every entry of a 398-report catalog) -- acceptanceType/state are the
        # only fields the list operation actually populates for filtering candidates.
        return r.get("acceptanceType") == "EXPLICIT" and r.get("state") == "PUBLISHED"

    open_reports = _find_reports(ctx, _is_open, want=40, max_items=300)
    if not open_reports:
        raise AssertionError("no EXPLICIT/PUBLISHED report found in the first 300 catalog entries")
    report_a = open_reports[0]
    term_a = art.get_term_for_report(reportId=report_a["id"])
    doc_a, token_a = term_a["documentPresignedUrl"].split("?", 1)[0], term_a["termToken"]
    token_b = None
    for candidate in open_reports[1:]:
        term_b = art.get_term_for_report(reportId=candidate["id"])
        if term_b["documentPresignedUrl"].split("?", 1)[0] != doc_a:
            token_b = term_b["termToken"]
            break
    if token_b is None:
        raise AssertionError(
            "no two EXPLICIT/PUBLISHED reports with different term documents found in the "
            "first 300 catalog entries; cannot construct a cross-term termToken pairing"
        )

    # Positive control: the correctly paired (reportId, termToken) works.
    ok = art.get_report(reportId=report_a["id"], termToken=token_a)
    assert ok["documentPresignedUrl"], f"expected a presigned document URL for the correctly paired call, got {ok!r}"

    err = _client_error(lambda: art.get_report(reportId=report_a["id"], termToken=token_b))
    assert err["Code"] == "ValidationException", f"expected ValidationException for mismatched termToken, got {err['Code']}"
    assert err.get("Message") == "The provided token is invalid.", (
        f"expected AWS's exact refusal message, got {err.get('Message')!r}"
    )


def _find_reports(ctx, predicate, want: int, max_items: int = 300):
    art = ctx.client("artifact")
    token = None
    seen = 0
    matches = []
    while seen < max_items and len(matches) < want:
        kwargs = {"maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = art.list_reports(**kwargs)
        for r in resp.get("reports", []):
            seen += 1
            if predicate(r):
                matches.append(r)
                if len(matches) >= want:
                    break
        token = resp.get("nextToken")
        if not token:
            break
    return matches


def _client_error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
