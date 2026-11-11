"""ui-customization-image-blob-byte-identical-round-trip."""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ui-customization-image-blob-byte-identical-round-trip"
GROUP = "representation"
SERVICES = ["cognito-idp"]

# A minimal valid 1x1 transparent PNG (67 bytes), used as the login image blob.
_PNG_BYTES = bytes.fromhex(
    "89504e470d0a1a0a0000000d494844520000000100000001080600000"
    "01f15c4890000000a49444154789c6360000002000155a9c9210000000049454e44ae426082"
)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """SetUICustomization's ImageFile blob is hosted unmodified: fetching UICustomization.ImageUrl
    returns byte-identical content to what was uploaded, and GetUICustomization reports it back."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-uipool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    domain = ctx.unique_name("sim2real-uidom-").lower().replace("_", "-")
    idp.create_user_pool_domain(Domain=domain, UserPoolId=pool_id, ManagedLoginVersion=1)

    def _cleanup_domain() -> None:
        idp.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id)
        # DeleteUserPoolDomain is asynchronous: DeleteUserPool immediately after (the next LIFO
        # cleanup) fails while the domain is still detaching, and ctx.on_cleanup swallows that
        # failure, silently leaking the pool. Wait for the domain to actually disappear.
        _wait_domain_gone(idp, domain, timeout_s=40.0)

    ctx.on_cleanup(_cleanup_domain)

    # SetUICustomization requires the pool to have a domain that has finished provisioning
    # (Status=ACTIVE); prefix domains provision in well under this bound.
    _wait_domain_exists(idp, domain, timeout_s=240.0)

    set_resp = _retry_set_ui_customization(
        idp, pool_id, css=".label-customizable { color: #123456; }", image=_PNG_BYTES, timeout_s=120.0
    )
    image_url = set_resp["UICustomization"]["ImageUrl"]
    assert image_url, "SetUICustomization did not return an ImageUrl for the uploaded blob"

    get_resp = idp.get_ui_customization(UserPoolId=pool_id, ClientId="ALL")
    assert get_resp["UICustomization"]["ImageUrl"] == image_url, (
        f"GetUICustomization reported ImageUrl {get_resp['UICustomization'].get('ImageUrl')!r}, "
        f"expected the SetUICustomization response's {image_url!r}"
    )
    assert get_resp["UICustomization"]["CSS"] == ".label-customizable { color: #123456; }", (
        f"GetUICustomization reported CSS {get_resp['UICustomization'].get('CSS')!r}, expected the uploaded CSS"
    )

    fetched = _poll_fetch_bytes(ctx, image_url, timeout_s=180.0, interval_s=10.0)
    assert fetched == _PNG_BYTES, "hosted image bytes differ from the uploaded ImageFile blob"


def _wait_domain_exists(idp, domain: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last_err = None
    last_status = None
    while time.monotonic() < deadline:
        try:
            desc = idp.describe_user_pool_domain(Domain=domain).get("DomainDescription") or {}
            last_status = desc.get("Status")
            if last_status == "ACTIVE":
                return
        except ClientError as err:  # noqa: PERF203
            last_err = err
        time.sleep(3.0)
    if last_status is not None and last_status != "ACTIVE":
        raise AssertionError(f"domain {domain} never reached ACTIVE within {timeout_s}s (last status={last_status!r})")
    if last_err is not None:
        raise last_err


def _wait_domain_gone(idp, domain: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            desc = idp.describe_user_pool_domain(Domain=domain).get("DomainDescription") or {}
        except ClientError:
            return
        if not desc.get("UserPoolId"):
            return
        last_status = desc.get("Status")
        time.sleep(3.0)
    raise AssertionError(f"domain {domain} still present {timeout_s}s after delete (last status={last_status!r})")


def _retry_set_ui_customization(idp, pool_id: str, css: str, image: bytes, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return idp.set_ui_customization(UserPoolId=pool_id, ClientId="ALL", CSS=css, ImageFile=image)
        except ClientError as err:  # noqa: PERF203
            code = err.response["Error"]["Code"]
            if code not in ("ResourceNotFoundException", "InvalidParameterException"):
                raise
            last_err = err
            time.sleep(5.0)
    raise AssertionError(f"SetUICustomization never succeeded within {timeout_s}s: {last_err}")


def _poll_fetch_bytes(ctx, url: str, timeout_s: float, interval_s: float) -> bytes:
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            _url, _route = ctx.endpoint_route(url)
            req = urllib.request.Request(_url, headers={**({"User-Agent": "sim2real-behavioral-check/1.0"}), **_route})
            with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
                return resp.read()
        except (urllib.error.URLError, urllib.error.HTTPError) as exc:  # noqa: PERF203
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"could not fetch hosted UI image from {url} within {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
