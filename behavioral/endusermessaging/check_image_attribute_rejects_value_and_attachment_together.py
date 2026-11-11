"""image-attribute-rejects-value-and-attachment-together."""
from __future__ import annotations

import base64

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "image-attribute-rejects-value-and-attachment-together"
GROUP = "brand-profile-attributes"
SERVICES = ["endusermessaging"]

# A 1x1 PNG, small enough to embed and byte-compare.
_PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUAcm3jRFoAAAAASUVORK5CYII="
)


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
    """An IMAGE attribute takes an S3 URL or an attachment, never both: such a create is refused
    with ValidationException, while the attachment alone is accepted.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-imgboth-")
    )["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    attr = "Logo Both"
    code, message = _error(lambda: eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": attr, "attributeType": "IMAGE",
         "attributeValue": "s3://amzn-s3-demo-bucket/logo.png", "attachmentBody": _PNG_BYTES}]))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == f"Only one of attributeValue or attachmentBody can be provided for attribute '{attr}'", (
        f"unexpected message {message!r}"
    )
    code, message = _error(lambda: eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=attr))
    assert code == "ResourceNotFoundException", f"the refused attribute exists: {code}: {message!r}"

    eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": attr, "attributeType": "IMAGE", "attachmentBody": _PNG_BYTES}])
    got = eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=attr)
    assert got.get("mediaContentType") == "image/png", f"positive control, got {got.get('mediaContentType')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
