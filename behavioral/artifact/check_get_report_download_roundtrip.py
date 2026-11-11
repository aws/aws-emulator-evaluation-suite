"""get-report-download-roundtrip."""
from __future__ import annotations

import urllib.request

from behavioral_harness import tags

CHECK = "get-report-download-roundtrip"
GROUP = "data-plane"
SERVICES = ["artifact"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """For a published report, GetTermForReport's termToken exchanged through GetReport yields a
    presigned URL whose download is a real PDF document."""
    art = ctx.client("artifact")
    report = _find_report(
        ctx,
        lambda r: r.get("acceptanceType") == "PASSTHROUGH"
        and r.get("state") == "PUBLISHED"
        and r.get("uploadState") in (None, "COMPLETE"),
    )
    if report is None:
        raise AssertionError(
            "no PASSTHROUGH/PUBLISHED report with a ready (absent-or-COMPLETE) uploadState "
            "found in the first 1000 catalog entries; cannot exercise the no-explicit-"
            "acceptance download flow"
        )

    term = art.get_term_for_report(reportId=report["id"])
    assert term["termToken"]
    assert term["documentPresignedUrl"]

    got = art.get_report(reportId=report["id"], termToken=term["termToken"])
    url = got["documentPresignedUrl"]
    assert url

    target_url, route_headers = ctx.endpoint_route(url)
    with urllib.request.urlopen(urllib.request.Request(target_url, headers=route_headers), timeout=30) as resp:
        status = resp.status
        content_type = resp.headers.get("Content-Type", "")
        body = resp.read(4096)
    assert status == 200, f"presigned document URL returned HTTP {status}"
    assert content_type == "application/pdf", f"expected application/pdf, got {content_type!r}"
    assert body.startswith(b"%PDF-"), (
        f"presigned document URL did not serve a PDF (first bytes={body[:16]!r})"
    )


def _find_report(ctx, predicate, max_items: int = 1000):
    art = ctx.client("artifact")
    token = None
    seen = 0
    while seen < max_items:
        kwargs = {"maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = art.list_reports(**kwargs)
        for r in resp.get("reports", []):
            seen += 1
            if predicate(r):
                return r
        token = resp.get("nextToken")
        if not token:
            break
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
