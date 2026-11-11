"""brand-profile-attribute-media-download-url-serves-uploaded-bytes."""
from __future__ import annotations

import base64

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "brand-profile-attribute-media-download-url-serves-uploaded-bytes"
GROUP = 'brand-profile-attributes'
SERVICES = ['endusermessaging']

# A 1x1 transparent PNG, small enough to embed and byte-compare.
_PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUAcm3jRFoAAAAASUVORK5CYII="
)


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
    """GetBrandProfileAttribute's mediaDownloadUrl, fetched over plain HTTP, serves back the
    exact bytes CreateBrandProfileAttributes uploaded; an attribute with no attachment gets no URL.
    """
    eum = ctx.client("endusermessaging")
    bp_name = ctx.unique_name("sim2real-behav-eum-media-")
    with_body_name = ctx.unique_name("sim2real-behav-eum-img-withbody-")
    no_body_name = ctx.unique_name("sim2real-behav-eum-img-nobody-")

    bpid = eum.create_brand_profile(brandProfileName=bp_name)["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))

    eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": with_body_name, "attributeType": "IMAGE", "attachmentBody": _PNG_BYTES},
        {"attributeName": no_body_name, "attributeType": "IMAGE"},
    ])

    with_body = eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=with_body_name)
    assert with_body.get("mediaContentType") == "image/png", (
        f"expected mediaContentType image/png, got {with_body.get('mediaContentType')!r}"
    )
    assert with_body.get("mediaSizeBytes") == len(_PNG_BYTES), (
        f"expected mediaSizeBytes {len(_PNG_BYTES)}, got {with_body.get('mediaSizeBytes')!r}"
    )
    download_url = with_body.get("mediaDownloadUrl")
    assert download_url, "expected a mediaDownloadUrl for an attribute created with an attachment"

    url, headers = ctx.endpoint_route(download_url)
    resp = requests.get(url, headers=headers, verify=ctx.http_verify, timeout=30)
    assert resp.status_code == 200, f"download answered {resp.status_code}: {resp.text[:200]!r}"
    assert resp.content == _PNG_BYTES, (
        f"downloaded {len(resp.content)} byte(s) that did not match the {len(_PNG_BYTES)} byte(s) uploaded"
    )

    no_body = eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=no_body_name)
    assert "mediaDownloadUrl" not in no_body, (
        f"expected no mediaDownloadUrl without an attachment, got {no_body.get('mediaDownloadUrl')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
