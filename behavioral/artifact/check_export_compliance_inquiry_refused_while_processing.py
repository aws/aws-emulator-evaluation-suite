"""export-compliance-inquiry-refused-while-processing."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-compliance-inquiry-refused-while-processing"
GROUP = "state-machine"
SERVICES = ["artifact"]

#: Fresh inquiries tried before the check gives up on observing the PROCESSING window. Artifact
#: has no API that deletes a compliance inquiry, so every attempt leaves one behind in the account.
_ATTEMPTS = 2
_REFUSAL = (
    "ValidationException",
    "Unable to export resource in a `PROCESSING` state. Please wait for processing to complete.",
)
_SETTLE_TIMEOUT_S = 180.0

#: The code _outcome reports for a call the target accepted.
_ACCEPTED = "accepted"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ExportComplianceInquiry on an inquiry still PROCESSING is refused with ValidationException,
    and the identical call returns a document URL once the inquiry is COMPLETED."""
    art = ctx.client("artifact")
    refusal = None
    tried = []
    inquiry_id = None
    for _ in range(_ATTEMPTS):
        # No cleanup: Artifact cannot delete a compliance inquiry, so it stays in the account.
        inquiry_id = art.create_compliance_inquiry(
            name=ctx.unique_name("sim2real-artifact-export-early-"),
            inquiryContent={"query": "Does AWS provide a HIPAA compliant environment?"},
            supportMode="AI_ONLY",
        )["complianceInquirySummary"]["id"]
        status = _status(art, inquiry_id)
        if status != "PROCESSING":
            tried.append(f"{inquiry_id}: {status} before the export")
            continue
        code, message = _outcome(lambda: art.export_compliance_inquiry(complianceInquiryId=inquiry_id))
        if code != _ACCEPTED:
            refusal = (code, message)
            break
        still = _status(art, inquiry_id)
        assert still != "PROCESSING", "ExportComplianceInquiry on an inquiry that stayed PROCESSING was accepted"
        tried.append(f"{inquiry_id}: export accepted after the inquiry left PROCESSING ({still!r})")
    assert refusal is not None, (
        f"never observed an export of a PROCESSING inquiry in {_ATTEMPTS} fresh inquiries: {tried!r}"
    )
    assert refusal == _REFUSAL, f"expected {_REFUSAL!r} exporting a PROCESSING inquiry, got {refusal!r}"

    # Positive control: the identical call succeeds once the inquiry completes.
    left = ctx.time_left()
    timeout = _SETTLE_TIMEOUT_S if left is None else max(1.0, min(_SETTLE_TIMEOUT_S, left - 30.0))
    deadline = time.monotonic() + timeout
    status = _status(art, inquiry_id)
    while status == "PROCESSING":
        assert time.monotonic() < deadline, (
            f"inquiry {inquiry_id} stayed PROCESSING for {timeout:.0f}s"
        )
        time.sleep(3)
        status = _status(art, inquiry_id)
    assert status == "COMPLETED", f"inquiry {inquiry_id} settled {status!r}, expected COMPLETED"
    url = art.export_compliance_inquiry(complianceInquiryId=inquiry_id)["documentPresignedUrl"]
    assert url.startswith("https://"), f"export of a COMPLETED inquiry returned {url!r}"


def _status(art, inquiry_id: str) -> str:
    return art.get_compliance_inquiry_metadata(complianceInquiryId=inquiry_id)["complianceInquiryDetail"]["status"]


def _outcome(fn) -> tuple[str, str | None]:
    """(code, message) of the refusal ``fn`` raises, or (_ACCEPTED, the response) when it is accepted."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return _ACCEPTED, repr(result)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
