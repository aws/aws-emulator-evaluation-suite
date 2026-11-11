"""document-attribute-created-without-attachment-gains-media-on-update."""
from __future__ import annotations

import requests

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "document-attribute-created-without-attachment-gains-media-on-update"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A DOCUMENT attribute created empty has no media; an update that supplies a PDF gives it
    media metadata and a download URL serving exactly those bytes.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-docadd-")
    )["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    attr = "policy"
    eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": attr, "attributeType": "DOCUMENT"}])
    empty = eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=attr)
    media_keys = {"mediaContentType", "mediaSizeBytes", "mediaDownloadUrl"}
    assert not media_keys & set(empty), f"an empty DOCUMENT reports media keys {sorted(media_keys & set(empty))!r}"

    eum.update_brand_profile_attribute(brandProfileId=bpid, attributeName=attr, attachmentBody=_PDF_BYTES)
    got = eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=attr)
    assert (got.get("mediaContentType"), got.get("mediaSizeBytes")) == ("application/pdf", len(_PDF_BYTES)), (
        f"after update: {got.get('mediaContentType')!r}, {got.get('mediaSizeBytes')!r}"
    )
    url, headers = ctx.endpoint_route(got["mediaDownloadUrl"])
    resp = requests.get(url, headers=headers, verify=ctx.http_verify, timeout=30)
    assert resp.status_code == 200, f"download answered {resp.status_code}"
    assert resp.content == _PDF_BYTES, f"served {len(resp.content)} byte(s), uploaded {len(_PDF_BYTES)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
