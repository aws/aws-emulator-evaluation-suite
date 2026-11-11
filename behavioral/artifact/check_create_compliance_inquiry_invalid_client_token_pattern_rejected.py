"""create-compliance-inquiry-invalid-client-token-pattern-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-compliance-inquiry-invalid-client-token-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["artifact"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateComplianceInquiry with a clientToken outside ^[\\w\\-]+$ fails BadRequestException and
    creates nothing, while a retry with a valid clientToken and the same query succeeds."""
    art = ctx.client("artifact")
    marker = ctx.unique_name("sim2real-artifact-badtoken-")
    query_text = f"What is AWS Artifact? [{marker}]"
    bad_token = "not a valid token!"

    captured = {}

    def _call():
        captured["resp"] = art.create_compliance_inquiry(
            name=marker,
            inquiryContent={"query": query_text},
            supportMode="AI_ONLY",
            clientToken=bad_token,
        )

    code, message = _error(_call)
    if code == "AccessDeniedException":
        raise AssertionError(
            "account is not opted into AWS Artifact Assurance Assistant "
            "(CreateComplianceInquiry requires feature opt-in); cannot exercise "
            "clientToken pattern validation"
        )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Invalid request body", f"expected AWS's exact refusal message, got {message!r}"
    assert "resp" not in captured, "a rejected create call must not return a created inquiry"

    # Confirm nothing was created under that query content despite the rejected call.
    assert not _name_in_list(art, query_text), (
        f"an inquiry with query content {query_text!r} exists despite a rejected create call"
    )

    # Positive control: the same query content with a valid clientToken succeeds and
    # is now visible in the listing.
    ok = art.create_compliance_inquiry(
        name=marker,
        inquiryContent={"query": query_text},
        supportMode="AI_ONLY",
        clientToken=ctx.unique_name("sim2real-artifact-goodtoken-"),
    )
    assert ok["complianceInquirySummary"]["id"].startswith("compliance-inquiry-")
    assert ok["complianceInquirySummary"]["arn"].startswith("arn:")
    assert _name_in_list(art, query_text), (
        f"inquiry with query content {query_text!r} not visible in list after a "
        "successful create"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it succeeded and returned {result!r}")


def _name_in_list(art, name, max_items: int = 900) -> bool:
    token = None
    scanned = 0
    while scanned < max_items:
        kwargs = {"maxResults": 300}
        if token:
            kwargs["nextToken"] = token
        page = art.list_compliance_inquiries(**kwargs)
        for item in page.get("complianceInquiries", []):
            scanned += 1
            if item["name"] == name:
                return True
        token = page.get("nextToken")
        if not token:
            break
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
