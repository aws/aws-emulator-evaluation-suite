"""media-attachment-rejects-unsupported-file-type."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "media-attachment-rejects-unsupported-file-type"
GROUP = "brand-profile-attributes"
SERVICES = ["endusermessaging"]

# The smallest byte sequence the service accepts as a PDF document.
_PDF_BYTES = b"%PDF-1.4\n%%EOF\n"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The service inspects attachment bytes: plain text is refused as an IMAGE or a DOCUMENT
    with ValidationException listing PDF, JPEG and PNG, while PDF bytes are accepted.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-ftype-")
    )["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    for attr_type, attr in (("IMAGE", "Text As Image"), ("DOCUMENT", "Text As Document")):
        code, message = _error(lambda: eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
            {"attributeName": attr, "attributeType": attr_type, "attachmentBody": b"plain text bytes"}]))
        assert code == "ValidationException", f"{attr_type}: expected ValidationException, got {code}: {message!r}"
        assert message == f"Unsupported file type for attribute '{attr}'. Allowed: PDF, JPEG, PNG", (
            f"{attr_type}: unexpected message {message!r}"
        )
        code, message = _error(lambda: eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=attr))
        assert code == "ResourceNotFoundException", f"{attr_type}: refused attribute exists: {code}"

    eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": "Real Document", "attributeType": "DOCUMENT", "attachmentBody": _PDF_BYTES}])
    got = eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName="Real Document")
    assert (got.get("mediaContentType"), got.get("mediaSizeBytes")) == ("application/pdf", len(_PDF_BYTES)), (
        f"positive control: {got.get('mediaContentType')!r}, {got.get('mediaSizeBytes')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
