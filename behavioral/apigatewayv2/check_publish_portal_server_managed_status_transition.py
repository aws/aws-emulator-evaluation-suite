"""publish-portal-server-managed-status-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "publish-portal-server-managed-status-transition"
GROUP = "server-side"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PublishPortal starts a server-managed build: GetPortal reports PUBLISH_IN_PROGRESS or
    PUBLISHED right after the call, and the portal reaches PUBLISHED with no further client
    action between PublishPortal and the GetPortal polls.
    """
    apigw = ctx.client("apigatewayv2")
    portal_id = _create_portal(ctx, apigw)

    apigw.publish_portal(PortalId=portal_id)
    status_after_start = apigw.get_portal(PortalId=portal_id)["PublishStatus"]
    assert status_after_start in ("PUBLISH_IN_PROGRESS", "PUBLISHED"), (
        f"GetPortal right after PublishPortal reported {status_after_start!r}"
    )

    final_status = _poll_until(
        lambda: apigw.get_portal(PortalId=portal_id)["PublishStatus"],
        lambda s: s in ("PUBLISHED", "PUBLISH_FAILED"),
        timeout_s=900,
        interval_s=15,
    )
    assert final_status == "PUBLISHED", f"managed publish did not reach PUBLISHED: {final_status}"


# ===== helpers =====
def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_portal(ctx, apigw):
    portal = apigw.create_portal(
        Authorization={"None": {}},
        EndpointConfiguration={"None": {}},
        PortalContent={
            "DisplayName": ctx.unique_name("sim2real-behav-portal-"),
            "Theme": {
                "CustomColors": {
                    "AccentColor": "#0000FF",
                    "BackgroundColor": "#FFFFFF",
                    "ErrorValidationColor": "#FF0000",
                    "HeaderColor": "#111111",
                    "NavigationColor": "#222222",
                    "TextColor": "#000000",
                }
            },
        },
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
    try:
        if status != "DISABLED":
            try:
                apigw.disable_portal(PortalId=portal_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NotFoundException":
                    raise
            deadline = time.monotonic() + 600
            while time.monotonic() < deadline:
                status = apigw.get_portal(PortalId=portal_id)["PublishStatus"]
                if status == "DISABLED":
                    break
                time.sleep(2)
        apigw.delete_portal(PortalId=portal_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
