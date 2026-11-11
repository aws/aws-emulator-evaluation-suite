"""image-attribute-value-must-be-an-s3-url."""
from __future__ import annotations

import base64

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "image-attribute-value-must-be-an-s3-url"
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
    """An IMAGE attribute's attributeValue must be an s3:// URL: a plain string is refused on
    create with ValidationException, and on update of an existing image too.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-imgval-")
    )["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    attr = "Logo Value"
    code, message = _error(lambda: eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": attr, "attributeType": "IMAGE", "attributeValue": "not a url"}]))
    assert code == "ValidationException", f"create: expected ValidationException, got {code}: {message!r}"
    assert message == f"attributeValue must be an S3 URL (s3://bucket/key) for IMAGE attribute '{attr}'", (
        f"create: unexpected message {message!r}"
    )

    eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": attr, "attributeType": "IMAGE", "attachmentBody": _PNG_BYTES}])
    code, message = _error(lambda: eum.update_brand_profile_attribute(
        brandProfileId=bpid, attributeName=attr, attributeValue="not a url"))
    assert code == "ValidationException", f"update: expected ValidationException, got {code}: {message!r}"
    assert message == "Either attributeValue (S3 URL) or attachmentBody must be provided for IMAGE attribute", (
        f"update: unexpected message {message!r}"
    )
    got = eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=attr)
    assert (got.get("mediaContentType"), got.get("mediaSizeBytes")) == ("image/png", len(_PNG_BYTES)), (
        f"the refused update changed the media: {got.get('mediaContentType')!r}, {got.get('mediaSizeBytes')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
