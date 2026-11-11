"""media-attribute-download-serves-sniffed-type-and-named-file."""
from __future__ import annotations

import base64

import requests

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "media-attribute-download-serves-sniffed-type-and-named-file"
GROUP = "brand-profile-attributes"
SERVICES = ["endusermessaging"]

# A 1x1 PNG, small enough to embed and byte-compare.
_PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUAcm3jRFoAAAAASUVORK5CYII="
)

# A 1x1 baseline JPEG.
_JPEG_BYTES = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwc"
    "KDcpLDAxNDQ0Hyc5PTgyPC4zNDL/wAALCAABAAEBAREA/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QA"
    "tRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0"
    "NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2"
    "t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/9oACAEBAAA/APvT/9k="
)

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


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Each media attribute is typed from its bytes: JPEG, PNG and PDF uploads report and serve
    their content type, size and an inline file name of attribute name plus extension.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-sniff-")
    )["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    uploads = [
        ("logo", "IMAGE", _JPEG_BYTES, "image/jpeg", "jpeg"),
        ("badge", "DOCUMENT", _PNG_BYTES, "image/png", "png"),
        ("terms", "DOCUMENT", _PDF_BYTES, "application/pdf", "pdf"),
    ]
    eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": n, "attributeType": t, "attachmentBody": b} for n, t, b, _, _ in uploads])

    for attr, _, body, content_type, ext in uploads:
        got = eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=attr)
        assert (got.get("mediaContentType"), got.get("mediaSizeBytes")) == (content_type, len(body)), (
            f"{attr}: {got.get('mediaContentType')!r}, {got.get('mediaSizeBytes')!r}"
        )
        url, headers = ctx.endpoint_route(got["mediaDownloadUrl"])
        resp = requests.get(url, headers=headers, verify=ctx.http_verify, timeout=30)
        assert resp.status_code == 200, f"{attr}: download answered {resp.status_code}"
        assert resp.content == body, f"{attr}: served {len(resp.content)} byte(s), uploaded {len(body)}"
        assert resp.headers.get("Content-Type") == content_type, (
            f"{attr}: served Content-Type {resp.headers.get('Content-Type')!r}"
        )
        assert resp.headers.get("Content-Disposition") == f'inline; filename="{attr}.{ext}"', (
            f"{attr}: served Content-Disposition {resp.headers.get('Content-Disposition')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
