"""disabled-portal-preview-accepted."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "disabled-portal-preview-accepted"
GROUP = "concurrency"
SERVICES = ["apigatewayv2"]
TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PreviewPortal is accepted both during an in-flight DisablePortal and once DISABLED, each time
    confirmed by PreviewStatus progressing; a never-disabled control portal behaves the same way.
    """
    apigw = ctx.client("apigatewayv2")

    # The disable runs asynchronously; a read that already shows it DISABLED missed the in-flight
    # window, so the scenario is re-armed on a fresh published portal, up to _ATTEMPTS.
    for _attempt in range(_ATTEMPTS):
        portal_id = _create_portal(ctx, apigw)
        apigw.publish_portal(PortalId=portal_id)
        _poll_until(
            lambda: apigw.get_portal(PortalId=portal_id)["PublishStatus"],
            lambda s: s == "PUBLISHED",
            timeout_s=_budget_s(ctx, 900),
            interval_s=15,
        )

        apigw.disable_portal(PortalId=portal_id)  # starts async DISABLE_IN_PROGRESS
        status_in_flight = apigw.get_portal(PortalId=portal_id)["PublishStatus"]
        if status_in_flight != "DISABLED":
            break
    assert status_in_flight == "DISABLE_IN_PROGRESS", status_in_flight

    apigw.preview_portal(PortalId=portal_id)  # accepted during an in-flight disable
    preview_in_flight = (apigw.get_portal(PortalId=portal_id).get("Preview") or {}).get("PreviewStatus")
    assert preview_in_flight in ("PREVIEW_IN_PROGRESS", "PREVIEW_READY"), preview_in_flight

    terminal_status = _poll_until(
        lambda: apigw.get_portal(PortalId=portal_id)["PublishStatus"],
        lambda s: s in ("DISABLED", "DISABLE_FAILED"),
        timeout_s=_budget_s(ctx, 900),
        interval_s=15,
    )
    assert terminal_status == "DISABLED", terminal_status

    apigw.preview_portal(PortalId=portal_id)  # accepted once the disable settled
    preview_after_disabled = (apigw.get_portal(PortalId=portal_id).get("Preview") or {}).get("PreviewStatus")
    assert preview_after_disabled in ("PREVIEW_IN_PROGRESS", "PREVIEW_READY"), preview_after_disabled

    # Positive control: disable has no effect on preview's availability.
    control_id = _create_portal(ctx, apigw)
    apigw.preview_portal(PortalId=control_id)
    control_preview = (apigw.get_portal(PortalId=control_id).get("Preview") or {}).get("PreviewStatus")
    assert control_preview in ("PREVIEW_IN_PROGRESS", "PREVIEW_READY"), control_preview


# ===== helpers =====
_ATTEMPTS = 3


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _custom_colors():
    return {
        "AccentColor": "#0000FF",
        "BackgroundColor": "#FFFFFF",
        "ErrorValidationColor": "#FF0000",
        "HeaderColor": "#111111",
        "NavigationColor": "#222222",
        "TextColor": "#000000",
    }


def _create_portal(ctx, apigw):
    portal = apigw.create_portal(
        Authorization={"None": {}},
        EndpointConfiguration={"None": {}},
        PortalContent={
            "DisplayName": ctx.unique_name("sim2real-behav-portal-"),
            "Theme": {"CustomColors": _custom_colors()},
        },
        Tags=TAGS,
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
