"""concurrent-portal-update-conflict."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-portal-update-conflict"
GROUP = "concurrency"
SERVICES = ["apigatewayv2"]

_TERMINAL_PUBLISH_STATES = {"PUBLISHED", "PUBLISH_FAILED"}
TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav-portal"}


def _theme():
    return {
        "CustomColors": {
            "AccentColor": "#0000FF",
            "BackgroundColor": "#FFFFFF",
            "ErrorValidationColor": "#FF0000",
            "HeaderColor": "#111111",
            "NavigationColor": "#222222",
            "TextColor": "#000000",
        }
    }


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdatePortal racing a just-started PublishPortal returns ConflictException with its effect
    absent, or is accepted and its effect lands; never another error or a dropped accept.
    UpdatePortal succeeds before the race and again once publishing settles."""
    apigw = ctx.client("apigatewayv2")

    name = ctx.unique_name("sim2real-behav-portal-")
    portal = apigw.create_portal(
        Authorization={"None": {}},
        EndpointConfiguration={"None": {}},
        PortalContent={"DisplayName": name, "Theme": _theme()},
        Tags=TAGS,
    )
    portal_id = portal["PortalId"]
    ctx.on_cleanup(lambda: _delete_portal(ctx, portal_id))

    # Positive control: UpdatePortal succeeds normally before any publish is in flight.
    baseline_name = name + "-baseline"
    baseline = apigw.update_portal(
        PortalId=portal_id, PortalContent={"DisplayName": baseline_name, "Theme": _theme()}
    )
    assert baseline["PortalContent"]["DisplayName"] == baseline_name, (
        f"expected the baseline UpdatePortal to take, got {baseline['PortalContent']['DisplayName']!r}"
    )

    apigw.publish_portal(PortalId=portal_id)

    # Race the update immediately against the just-started (documented async) publish. AWS does
    # not guarantee the build is still in flight by the time this lands, so either a specific,
    # scoped rejection (busy, effect absent) or an accepted-and-applied update is legitimate --
    # never any other error, and never accepted-then-dropped.
    race_name = name + "-race"
    outcome = _try_call(
        lambda: apigw.update_portal(
            PortalId=portal_id, PortalContent={"DisplayName": race_name, "Theme": _theme()}
        )
    )
    if outcome[0] == "ok":
        landed = apigw.get_portal(PortalId=portal_id)
        assert landed["PortalContent"]["DisplayName"] == race_name, (
            f"UpdatePortal was accepted but never took effect: expected {race_name!r}, "
            f"got {landed['PortalContent']['DisplayName']!r}"
        )
    else:
        assert outcome == ("error", "ConflictException"), (
            f"unexpected outcome racing UpdatePortal against an in-flight PublishPortal: {outcome}"
        )
        mid_flight = apigw.get_portal(PortalId=portal_id)
        assert mid_flight["PortalContent"]["DisplayName"] == baseline_name, (
            f"expected the pre-race name {baseline_name!r} to survive the rejected race, "
            f"got {mid_flight['PortalContent']['DisplayName']!r}"
        )

    _poll_publish_terminal(ctx, portal_id, timeout_s=600.0)

    # Restore: once publish settles, the identical kind of call succeeds again -- proved by an
    # independent GetPortal read, not by the mutating call's own echoed response.
    after_name = name + "-after"
    apigw.update_portal(PortalId=portal_id, PortalContent={"DisplayName": after_name, "Theme": _theme()})
    restored = apigw.get_portal(PortalId=portal_id)
    assert restored["PortalContent"]["DisplayName"] == after_name, (
        f"expected UpdatePortal to take effect once publish settled, "
        f"got {restored['PortalContent']['DisplayName']!r}"
    )


def _try_call(fn):
    try:
        fn()
        return ("ok", None)
    except ClientError as exc:
        return ("error", exc.response["Error"]["Code"])


def _poll_publish_terminal(ctx, portal_id: str, timeout_s: float) -> str:
    apigw = ctx.client("apigatewayv2")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = apigw.get_portal(PortalId=portal_id)["PublishStatus"]
        if status in _TERMINAL_PUBLISH_STATES:
            return status
        time.sleep(3.0)
    raise AssertionError(f"publish never reached a terminal state within {timeout_s}s (last={status!r})")


def _delete_portal(ctx, portal_id: str) -> None:
    apigw = ctx.client("apigatewayv2")
    try:
        status = apigw.get_portal(PortalId=portal_id)["PublishStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
        return
    if status not in ("DISABLED",):
        try:
            apigw.disable_portal(PortalId=portal_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
        deadline = time.monotonic() + 300.0
        while time.monotonic() < deadline:
            try:
                status = apigw.get_portal(PortalId=portal_id)["PublishStatus"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NotFoundException":
                    raise
                return
            if status in ("DISABLED", "DISABLE_FAILED"):
                break
            time.sleep(2.0)
    try:
        apigw.delete_portal(PortalId=portal_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
