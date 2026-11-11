"""update-media-attribute-attachment-replaces-served-bytes."""
from __future__ import annotations

import base64

import requests

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-media-attribute-attachment-replaces-served-bytes"
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
    """UpdateBrandProfileAttribute with a new attachment replaces an IMAGE's media: the fresh
    download URL serves the new PNG bytes and type in place of the original JPEG.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-replace-")
    )["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    attr = "logo"
    eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": attr, "attributeType": "IMAGE", "attachmentBody": _JPEG_BYTES}])
    before = eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=attr)
    assert before.get("mediaContentType") == "image/jpeg", f"before: {before.get('mediaContentType')!r}"

    updated = eum.update_brand_profile_attribute(brandProfileId=bpid, attributeName=attr,
                                                 attachmentBody=_PNG_BYTES)
    assert (updated.get("mediaContentType"), updated.get("mediaSizeBytes")) == ("image/png", len(_PNG_BYTES)), (
        f"update answered {updated.get('mediaContentType')!r}, {updated.get('mediaSizeBytes')!r}"
    )

    after = eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=attr)
    url, headers = ctx.endpoint_route(after["mediaDownloadUrl"])
    resp = requests.get(url, headers=headers, verify=ctx.http_verify, timeout=30)
    assert resp.status_code == 200, f"download answered {resp.status_code}"
    assert resp.content == _PNG_BYTES, (
        f"served {len(resp.content)} byte(s); the replacement PNG is {len(_PNG_BYTES)}"
    )
    assert resp.headers.get("Content-Type") == "image/png", f"Content-Type {resp.headers.get('Content-Type')!r}"
    assert resp.headers.get("Content-Disposition") == 'inline; filename="logo.png"', (
        f"Content-Disposition {resp.headers.get('Content-Disposition')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
