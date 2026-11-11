"""disabled-portal-publish-accepted."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disabled-portal-publish-accepted"
GROUP = "overly-permissive"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PublishPortal during an in-flight DisablePortal is either accepted and really reaches
    PUBLISHED, or rejected with ConflictException leaving the disable intact; never another error.
    Once the disable has settled, the publish is accepted and reaches PUBLISHED.
    """
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    apigw = ctx.client("apigatewayv2")

    portal_id = _create_portal(ctx, apigw, teardown_deadline)
    apigw.publish_portal(PortalId=portal_id)
    _poll_until(
        lambda: apigw.get_portal(PortalId=portal_id)["PublishStatus"],
        lambda s: s == "PUBLISHED",
        timeout_s=900,
        interval_s=15,
    )

    apigw.disable_portal(PortalId=portal_id)  # starts async DISABLE_IN_PROGRESS
    pre_status = apigw.get_portal(PortalId=portal_id)["PublishStatus"]
    assert pre_status in ("DISABLE_IN_PROGRESS", "DISABLED"), (
        f"disable_portal left the portal neither mid-disable nor disabled (got {pre_status!r})"
    )

    outcome = _try_call(lambda: apigw.publish_portal(PortalId=portal_id))
    # A disable that has already settled leaves no race: a DISABLED portal accepts a publish.
    allowed = (("ok", 202), ("error", "ConflictException")) if pre_status == "DISABLE_IN_PROGRESS" else (("ok", 202),)
    assert outcome in allowed, (
        f"unexpected outcome for a PublishPortal issued during {pre_status}: {outcome}"
    )

    if outcome[0] == "error":
        # effect absent: the rejected publish did not push the portal back toward
        # a publishing/published state while the disable is in flight.
        status = apigw.get_portal(PortalId=portal_id)["PublishStatus"]
        assert status in ("DISABLE_IN_PROGRESS", "DISABLED", "DISABLE_FAILED"), status
    else:
        # AWS accepts the concurrent publish (DisablePortal does not lock the portal), so an
        # accepted publish must actually drive the portal to PUBLISHED, overriding the disable.
        settled = _poll_until(
            lambda: apigw.get_portal(PortalId=portal_id)["PublishStatus"],
            lambda s: s in ("PUBLISHED", "DISABLED", "DISABLE_FAILED"),
            timeout_s=900,
            interval_s=10,
        )
        assert settled == "PUBLISHED", (
            f"PublishPortal was accepted during {pre_status} but never took effect: {settled}"
        )

    # positive control: an uncontested portal accepts PublishPortal normally.
    control_id = _create_portal(ctx, apigw, teardown_deadline)
    apigw.publish_portal(PortalId=control_id)  # must not raise
    control_status = apigw.get_portal(PortalId=control_id)["PublishStatus"]
    assert control_status in ("PUBLISH_IN_PROGRESS", "PUBLISHED"), control_status


# ===== helpers =====
def _try_call(fn):
    try:
        resp = fn()
        return ("ok", resp["ResponseMetadata"]["HTTPStatusCode"])
    except ClientError as e:
        return ("error", e.response["Error"]["Code"])


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
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
            "HeaderColor": "#223344",
            "NavigationColor": "#334455",
            "TextColor": "#000000",
        }
    }


def _create_portal(ctx, apigw, teardown_deadline):
    portal = apigw.create_portal(
        Authorization={"None": {}},
        EndpointConfiguration={"None": {}},
        PortalContent={
            "DisplayName": ctx.unique_name("sim2real-behav-portal-"),
            "Theme": _theme(),
        },
        Tags={"sim2real-check": CHECK},
    )
    portal_id = portal["PortalId"]
    ctx.on_cleanup(lambda: _disable_and_delete_portal(apigw, portal_id, teardown_deadline))
    return portal_id


# budget.cleanup_timeout for behavioral/apigatewayv2, one deadline shared by every teardown of a run.
_TEARDOWN_RETRY_S = 900.0


def _portal_status(apigw, portal_id):
    """The portal's PublishStatus ("" when it was never published), or None once it is gone."""
    try:
        return apigw.get_portal(PortalId=portal_id).get("PublishStatus", "")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
        return None


def _disable_and_delete_portal(apigw, portal_id, teardown_deadline):
    """Wait out an in-flight publish or disable, DisablePortal (ConflictException until publishing
    ends, retried every 2 s), wait for DISABLED, then DeletePortal, all to the shared cleanup deadline."""
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)
    status = _portal_status(apigw, portal_id)
    while status not in (None, "", "DISABLED"):
        if status in ("PUBLISHED", "PUBLISH_FAILED", "DISABLE_FAILED"):
            try:
                apigw.disable_portal(PortalId=portal_id)
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "NotFoundException":
                    return
                if code != "ConflictException":
                    raise
        if time.monotonic() >= deadline:
            raise RuntimeError(f"portal {portal_id} not DISABLED before the cleanup deadline: {status}")
        time.sleep(2)
        status = _portal_status(apigw, portal_id)
    if status is None:
        return
    try:
        apigw.delete_portal(PortalId=portal_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
