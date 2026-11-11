"""disable-portal-revokes-access-server-side."""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "disable-portal-revokes-access-server-side"
GROUP = "server-side"
SERVICES = ["apigatewayv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """DisablePortal takes the portal's website offline, not just its PublishStatus: the default
    domain serves 200 while published and stops serving 200 after DisablePortal.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-portals-disable-portal.html"""
    apigw = ctx.client("apigatewayv2")
    portal_id = _create_portal(ctx, apigw)

    apigw.publish_portal(PortalId=portal_id)
    _poll_until(
        ctx,
        lambda: apigw.get_portal(PortalId=portal_id)["PublishStatus"],
        lambda s: s == "PUBLISHED",
        timeout_s=900,
    )

    portal = apigw.get_portal(PortalId=portal_id)
    domain = portal["EndpointConfiguration"]["PortalDefaultDomainName"]
    url = f"{ctx.endpoint_url(domain)}/"

    status_while_published = _poll_until(
        ctx, lambda: _probe(url), lambda s: s == 200, timeout_s=600
    )
    assert status_while_published == 200, (
        f"expected the published portal site to serve 200, got {status_while_published}"
    )

    apigw.disable_portal(PortalId=portal_id)
    _poll_until(
        ctx,
        lambda: apigw.get_portal(PortalId=portal_id)["PublishStatus"],
        lambda s: s == "DISABLED",
        timeout_s=900,
    )

    status_while_disabled = _poll_until(
        ctx, lambda: _probe(url), lambda s: s != 200, timeout_s=600
    )
    assert status_while_disabled != 200, (
        f"expected the portal site to stop serving 200 after DisablePortal, "
        f"still got {status_while_disabled}"
    )

    # The revocation must hold, not just blip once mid-propagation: the portal still reads
    # DISABLED and three consecutive follow-up requests all stay non-200.
    assert apigw.get_portal(PortalId=portal_id)["PublishStatus"] == "DISABLED", (
        "expected GetPortal to keep reporting PublishStatus DISABLED after DisablePortal"
    )
    for _ in range(3):
        still_disabled = _probe(url)
        assert still_disabled != 200, (
            f"portal site started serving 200 again shortly after DisablePortal "
            f"(got {still_disabled} on a follow-up probe) -- revocation did not hold"
        )


def _probe(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "sim2real-behavioral-check"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except urllib.error.URLError:
        return None  # DNS/connection unreachable -- also "not available"


def _poll_until(ctx, probe, predicate, timeout_s=60.0, interval_s=2.0):
    """Poll every ``interval_s`` until ``predicate`` holds; the deadline is capped by the run budget."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _theme():
    return {
        "CustomColors": {
            "AccentColor": "#112233",
            "BackgroundColor": "#ffffff",
            "ErrorValidationColor": "#ff0000",
            "HeaderColor": "#000000",
            "NavigationColor": "#333333",
            "TextColor": "#111111",
        }
    }


def _create_portal(ctx, apigw):
    portal = apigw.create_portal(
        Authorization={"None": {}},
        EndpointConfiguration={"None": {}},
        PortalContent={
            "DisplayName": ctx.unique_name("sim2real-behav-portal-"),
            "Theme": _theme(),
        },
        Tags={"sim2real": CHECK},
    )
    portal_id = portal["PortalId"]
    ctx.on_cleanup(lambda: _disable_and_delete_portal(apigw, portal_id))
    return portal_id


def _disable_and_delete_portal(apigw, portal_id):
    from botocore.exceptions import ClientError

    try:
        status = apigw.get_portal(PortalId=portal_id)["PublishStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
        return
    if status != "DISABLED":
        try:
            apigw.disable_portal(PortalId=portal_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
        deadline = time.monotonic() + 900
        while True:
            status = apigw.get_portal(PortalId=portal_id)["PublishStatus"]
            if status == "DISABLED":
                break
            if time.monotonic() >= deadline:
                raise RuntimeError(f"portal {portal_id} never reached DISABLED during teardown (last {status!r})")
            time.sleep(2)
    try:
        apigw.delete_portal(PortalId=portal_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
