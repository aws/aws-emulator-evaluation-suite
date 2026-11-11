"""compliance-inquiry-appears-in-list."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "compliance-inquiry-appears-in-list"
GROUP = "state"
SERVICES = ["artifact"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new compliance inquiry appears in ListComplianceInquiries with its id and the name
    CreateComplianceInquiry returned (the service derives a TEXT inquiry's name from its query)."""
    art = ctx.client("artifact")
    name = ctx.unique_name("sim2real-artifact-listmem-")
    inquiry = _create_inquiry(ctx, name, "What is included in the ISO 27001 certification scope?")
    inquiry_id = inquiry["id"]

    found = None
    token = None
    scanned = 0
    while scanned < 900:
        kwargs = {"maxResults": 300}
        if token:
            kwargs["nextToken"] = token
        page = art.list_compliance_inquiries(**kwargs)
        for item in page.get("complianceInquiries", []):
            scanned += 1
            if item["id"] == inquiry_id:
                found = item
                break
        if found is not None:
            break
        token = page.get("nextToken")
        if not token:
            break

    assert found is not None, f"created inquiry {inquiry_id} did not appear in ListComplianceInquiries"
    assert found["name"] == inquiry["name"], (
        f"list entry name {found['name']!r} does not match the name returned by "
        f"CreateComplianceInquiry {inquiry['name']!r}"
    )
    assert found["arn"] == inquiry["arn"], (
        f"list entry arn {found['arn']!r} does not match the arn returned by "
        f"CreateComplianceInquiry {inquiry['arn']!r}"
    )


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
                "(CreateComplianceInquiry requires feature opt-in); cannot create an "
                "inquiry to verify list membership"
            ) from e
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
