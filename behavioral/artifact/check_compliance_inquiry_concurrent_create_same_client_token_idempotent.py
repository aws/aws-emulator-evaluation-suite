"""compliance-inquiry-concurrent-create-same-client-token-idempotent."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "compliance-inquiry-concurrent-create-same-client-token-idempotent"
GROUP = "concurrency"
SERVICES = ["artifact"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing CreateComplianceInquiry calls with one clientToken and payload return the same inquiry
    id, and ListComplianceInquiries shows that id exactly once."""
    art = ctx.client("artifact")
    name = ctx.unique_name("sim2real-artifact-concur-")
    token = ctx.unique_name("sim2real-artifact-concur-tok-")
    query_text = "What is the AWS Artifact service used for?"

    # Warm-up single call first so an AccessDeniedException (feature not opted in)
    # surfaces as a clean skip rather than N racing failures.
    try:
        art.create_compliance_inquiry(
            name=name, inquiryContent={"query": query_text}, supportMode="AI_ONLY", clientToken=token
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            raise AssertionError(
                "account is not opted into AWS Artifact Assurance Assistant "
                "(CreateComplianceInquiry requires feature opt-in); cannot exercise "
                "concurrent-create idempotency"
            ) from e
        raise

    def _create():
        return art.create_compliance_inquiry(
            name=name, inquiryContent={"query": query_text}, supportMode="AI_ONLY", clientToken=token
        )["complianceInquirySummary"]["id"]

    n_racers = 5
    ids = []
    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        futures = [pool.submit(_create) for _ in range(n_racers)]
        for f in as_completed(futures):
            ids.append(f.result())

    assert len(ids) == n_racers, f"expected {n_racers} racing responses, got {len(ids)}"
    unique_ids = set(ids)
    assert len(unique_ids) == 1, f"racing calls with the same clientToken produced distinct inquiry ids: {unique_ids}"

    inquiry_id = unique_ids.pop()
    count = 0
    token_page = None
    scanned = 0
    while scanned < 900:
        kwargs = {"maxResults": 300}
        if token_page:
            kwargs["nextToken"] = token_page
        page = art.list_compliance_inquiries(**kwargs)
        for item in page.get("complianceInquiries", []):
            scanned += 1
            if item["id"] == inquiry_id:
                count += 1
        token_page = page.get("nextToken")
        if not token_page:
            break

    assert count == 1, f"expected exactly one listed inquiry for id {inquiry_id}, found {count}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
