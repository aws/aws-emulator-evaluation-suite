"""export-compliance-inquiry-after-terminal."""
from __future__ import annotations

import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-compliance-inquiry-after-terminal"
GROUP = "data-plane"
SERVICES = ["artifact"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """ExportComplianceInquiry, once the inquiry has reached a terminal state, returns
    a presigned URL that serves a real document over HTTP."""
    art = ctx.client("artifact")
    name = ctx.unique_name("sim2real-artifact-export-")
    inquiry = _create_inquiry(ctx, name, "What penetration testing reports are available for EC2?")
    inquiry_id = inquiry["id"]

    status = _poll_until(
        lambda: art.get_compliance_inquiry_metadata(complianceInquiryId=inquiry_id)[
            "complianceInquiryDetail"
        ]["status"],
        lambda status: status in ("COMPLETED", "FAILED"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert status == "COMPLETED", (
        f"inquiry reached a terminal state but did not complete (status={status}); "
        "export is only exercised against a completed inquiry"
    )

    exported = art.export_compliance_inquiry(complianceInquiryId=inquiry_id)
    url = exported["documentPresignedUrl"]
    assert url, f"export_compliance_inquiry returned no documentPresignedUrl: {exported!r}"

    target_url, route_headers = ctx.endpoint_route(url)
    with urllib.request.urlopen(urllib.request.Request(target_url, headers=route_headers), timeout=30) as resp:
        status = resp.status
        body = resp.read(4096)
    assert status == 200, f"exported document URL returned HTTP {status}"
    assert len(body) > 0, "exported document URL returned an empty body"


def _create_inquiry(ctx, name, query_text, support_mode="AI_ONLY"):
    art = ctx.client("artifact")
    try:
        return art.create_compliance_inquiry(
            name=name,
            inquiryContent={"query": query_text},
            supportMode=support_mode,
        )["complianceInquirySummary"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            raise AssertionError(
                "account is not opted into AWS Artifact Assurance Assistant "
                "(CreateComplianceInquiry requires feature opt-in); cannot exercise "
                "the export flow"
            ) from e
        raise


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
