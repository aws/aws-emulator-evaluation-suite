"""portal-lifecycle-crud."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "portal-lifecycle-crud"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePortal -> GetPortal shows an unpublished state -> UpdatePortal mutates the portal
    content -> DeletePortal -> GetPortal returns NotFoundException."""
    apigw = ctx.client("apigatewayv2")
    display_name = ctx.unique_name("sim2real-behav-portal-")
    theme = _theme()

    created = apigw.create_portal(
        Authorization={"None": {}},
        EndpointConfiguration={"None": {}},
        PortalContent={"DisplayName": display_name, "Theme": theme},
    )
    portal_id = created["PortalId"]
    assert created["PortalContent"]["DisplayName"] == display_name, (
        f"expected DisplayName={display_name!r}, got {created['PortalContent'].get('DisplayName')!r}"
    )
    # a freshly-created portal that has never been published reports DISABLED, not PUBLISHED
    assert created.get("PublishStatus") == "DISABLED", (
        f"expected PublishStatus='DISABLED' on create, got {created.get('PublishStatus')!r}"
    )

    def _cleanup():
        _disable_portal_if_needed(apigw, portal_id)
        try:
            apigw.delete_portal(PortalId=portal_id)
        except apigw.exceptions.NotFoundException:
            pass

    ctx.on_cleanup(_cleanup)

    got = apigw.get_portal(PortalId=portal_id)
    assert got["PortalContent"]["DisplayName"] == display_name, (
        f"expected DisplayName={display_name!r} on independent read, got "
        f"{got['PortalContent'].get('DisplayName')!r}"
    )
    assert got.get("PublishStatus") == "DISABLED", (
        f"expected PublishStatus='DISABLED' on independent read, got {got.get('PublishStatus')!r}"
    )

    new_display = f"{display_name}-v2"
    updated = apigw.update_portal(
        PortalId=portal_id, PortalContent={"DisplayName": new_display, "Theme": theme}
    )
    assert updated["PortalContent"]["DisplayName"] == new_display, (
        f"expected updated DisplayName={new_display!r}, got "
        f"{updated['PortalContent'].get('DisplayName')!r}"
    )

    got2 = apigw.get_portal(PortalId=portal_id)
    assert got2["PortalContent"]["DisplayName"] == new_display, (
        f"expected DisplayName={new_display!r} on post-update independent read, got "
        f"{got2['PortalContent'].get('DisplayName')!r}"
    )

    _disable_portal_if_needed(apigw, portal_id)
    apigw.delete_portal(PortalId=portal_id)

    _poll_until(
        lambda: _portal_exists(apigw, portal_id),
        lambda exists: not exists,
        timeout_s=120.0,
        interval_s=5.0,
    )
    err = _error(lambda: apigw.get_portal(PortalId=portal_id))
    assert err == ("NotFoundException", "Portal not found"), (
        f"expected NotFoundException on GetPortal after delete, got {err!r}"
    )

    # A mutation on the dead id must also fail, not just a read.
    mutate_err = _error(
        lambda: apigw.update_portal(
            PortalId=portal_id, PortalContent={"DisplayName": new_display, "Theme": theme}
        )
    )
    assert mutate_err == ("NotFoundException", "Portal not found"), (
        f"expected NotFoundException from UpdatePortal on a deleted portal, got {mutate_err!r}"
    )


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _portal_exists(apigw, portal_id) -> bool:
    try:
        apigw.get_portal(PortalId=portal_id)
    except apigw.exceptions.NotFoundException:
        return False
    return True


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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")



def _disable_portal_if_needed(apigw, portal_id):
    from botocore.exceptions import ClientError

    try:
        apigw.disable_portal(PortalId=portal_id)
    except ClientError as e:
        # a portal that was never published (or already disabled) has nothing to disable
        if e.response["Error"]["Code"] in (
            "BadRequestException",
            "NotFoundException",
            "ConflictException",
        ):
            return
        raise


    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline:
        try:
            status = apigw.get_portal(PortalId=portal_id).get("PublishStatus")
        except ClientError:
            return
        if status in ("DISABLED", "DISABLE_FAILED"):
            return
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
