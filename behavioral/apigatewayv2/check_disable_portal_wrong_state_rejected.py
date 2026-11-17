"""disable-portal-wrong-state-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disable-portal-wrong-state-rejected"
GROUP = "error-semantics"
SERVICES = ["apigatewayv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisablePortal on a never-published portal fails ConflictException and leaves it
    DISABLED; once the portal reaches PUBLISHED, the identical DisablePortal call succeeds.
    """
    apigw = ctx.client("apigatewayv2")
    portal_id = _create_portal(ctx, apigw)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_portal(PortalId=portal_id)))

    created_status = apigw.get_portal(PortalId=portal_id)["PublishStatus"]
    assert created_status == "DISABLED", (
        f"a freshly created portal must start DISABLED, got {created_status!r}"
    )

    code, message = _error(lambda: apigw.disable_portal(PortalId=portal_id))
    assert code == "ConflictException", (
        f"DisablePortal on a never-published portal: expected ConflictException, got "
        f"{code!r}: {message!r}"
    )
    assert message == (
        "Portal must be PUBLISHED, PUBLISH_FAILED, or DISABLE_FAILED to disable"
    ), f"unexpected message {message!r}"

    unchanged = apigw.get_portal(PortalId=portal_id)["PublishStatus"]
    assert unchanged == "DISABLED", (
        f"the refused DisablePortal must leave PublishStatus DISABLED, got {unchanged!r}"
    )

    apigw.publish_portal(PortalId=portal_id)
    _poll_until(
        lambda: apigw.get_portal(PortalId=portal_id)["PublishStatus"],
        lambda s: s in ("PUBLISHED", "PUBLISH_FAILED"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    published_status = apigw.get_portal(PortalId=portal_id)["PublishStatus"]
    assert published_status == "PUBLISHED", (
        f"managed publish did not reach PUBLISHED: {published_status!r}"
    )

    # the identical call now succeeds once the portal is in a disable-eligible state.
    apigw.disable_portal(PortalId=portal_id)
    final_status = _poll_until(
        lambda: apigw.get_portal(PortalId=portal_id)["PublishStatus"],
        lambda s: s == "DISABLED",
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert final_status == "DISABLED", (
        f"DisablePortal on a PUBLISHED portal must reach DISABLED, got {final_status!r}"
    )


def _error(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


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
    created = apigw.create_portal(
        Authorization={"None": {}},
        EndpointConfiguration={"None": {}},
        PortalContent={
            "DisplayName": ctx.unique_name("sim2real-portal-"),
            "Theme": {
                "CustomColors": {
                    "AccentColor": "#112233",
                    "BackgroundColor": "#ffffff",
                    "ErrorValidationColor": "#ff0000",
                    "HeaderColor": "#223344",
                    "NavigationColor": "#334455",
                    "TextColor": "#000000",
                }
            },
        },
    )
    return created["PortalId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
