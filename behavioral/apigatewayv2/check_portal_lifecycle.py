"""portal-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "portal-lifecycle"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePortal is gettable, UpdatePortal mutates PortalContent, DeletePortal -> NotFoundException."""
    apigw = ctx.client("apigatewayv2")

    theme = {
        "CustomColors": {
            "AccentColor": "#112233",
            "BackgroundColor": "#ffffff",
            "ErrorValidationColor": "#ff0000",
            "HeaderColor": "#223344",
            "NavigationColor": "#334455",
            "TextColor": "#000000",
        }
    }
    display_name = ctx.unique_name("sim2real-portal-")
    created = apigw.create_portal(
        Authorization={"None": {}},
        EndpointConfiguration={"None": {}},
        PortalContent={
            "DisplayName": display_name,
            "Description": "initial description",
            "Theme": theme,
        },
    )
    portal_id = created["PortalId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_portal(PortalId=portal_id)))
    assert created["PortalContent"]["DisplayName"] == display_name, (
        f"CreatePortal should echo the requested DisplayName {display_name!r}, "
        f"got {created['PortalContent']['DisplayName']!r}"
    )
    # Unpublished by default (no PublishPortal call was made yet).
    assert created["PublishStatus"] == "DISABLED", (
        f"a freshly created, never-published portal should report PublishStatus DISABLED, "
        f"got {created['PublishStatus']!r}"
    )

    got = apigw.get_portal(PortalId=portal_id)
    assert got["PortalContent"]["DisplayName"] == display_name, (
        f"GetPortal should show the persisted DisplayName {display_name!r}, "
        f"got {got['PortalContent']['DisplayName']!r}"
    )

    new_display_name = ctx.unique_name("sim2real-portal-upd-")
    updated = apigw.update_portal(
        PortalId=portal_id,
        PortalContent={
            "DisplayName": new_display_name,
            "Description": "updated description",
            "Theme": theme,
        },
    )
    assert updated["PortalContent"]["DisplayName"] == new_display_name, (
        f"UpdatePortal should echo the new DisplayName {new_display_name!r}, "
        f"got {updated['PortalContent']['DisplayName']!r}"
    )
    assert updated["PortalContent"]["Description"] == "updated description", (
        f"UpdatePortal should echo the new Description, got {updated['PortalContent']['Description']!r}"
    )

    got2 = apigw.get_portal(PortalId=portal_id)
    assert got2["PortalContent"]["DisplayName"] == new_display_name, (
        f"GetPortal should show the persisted post-update DisplayName {new_display_name!r}, "
        f"got {got2['PortalContent']['DisplayName']!r}"
    )
    assert got2["PortalContent"]["Description"] == "updated description", (
        f"GetPortal should show the persisted post-update Description, got {got2['PortalContent']['Description']!r}"
    )

    apigw.delete_portal(PortalId=portal_id)
    _poll_until(
        lambda: _portal_exists(apigw, portal_id),
        lambda exists: not exists,
        timeout_s=60.0,
        interval_s=3.0,
    )
    code, message = _error(lambda: apigw.get_portal(PortalId=portal_id))
    assert code == "NotFoundException", (
        f"expected GetPortal on a deleted portal to raise NotFoundException, got {code!r}: {message!r}"
    )
    assert message == "Portal not found", f"unexpected GetPortal refusal message {message!r}"

    # Gone also means unusable: a mutation against the dead id must be rejected too, never
    # silently accepted or resurrect the portal.
    mutate_code, mutate_message = _error(
        lambda: apigw.update_portal(
            PortalId=portal_id,
            PortalContent={"DisplayName": "post-delete", "Theme": theme},
        )
    )
    assert mutate_code == "NotFoundException", (
        f"expected UpdatePortal on a deleted portal id to raise NotFoundException, got "
        f"{mutate_code!r}: {mutate_message!r}"
    )
    assert mutate_message == "Portal not found", (
        f"unexpected UpdatePortal refusal message {mutate_message!r}"
    )


# ===== helpers =====
def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
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


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 3.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
