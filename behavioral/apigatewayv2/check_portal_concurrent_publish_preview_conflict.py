"""portal-concurrent-publish-preview-conflict."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "portal-concurrent-publish-preview-conflict"
GROUP = "concurrency"
SERVICES = ["apigatewayv2"]
TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-portal"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second PublishPortal while the first is in flight is accepted or rejected with
    ConflictException, never another error; PreviewPortal gets one of the same two outcomes."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    apigwv2 = ctx.client("apigatewayv2")
    portal_id = _create_portal(ctx, teardown_deadline)

    first = apigwv2.publish_portal(PortalId=portal_id)
    first_status = first["ResponseMetadata"]["HTTPStatusCode"]
    assert first_status == 202, f"expected the initial PublishPortal to be accepted with 202, got {first_status}"

    second_outcome = _try_call(lambda: apigwv2.publish_portal(PortalId=portal_id))
    assert second_outcome in (("ok", 202), ("error", "ConflictException")), (
        f"unexpected outcome for a PublishPortal issued while one is already in-flight: {second_outcome}"
    )

    preview_outcome = _try_call(lambda: apigwv2.preview_portal(PortalId=portal_id))
    assert preview_outcome in (("ok", 202), ("error", "ConflictException")), (
        f"unexpected outcome for a PreviewPortal issued while a publish is in-flight: {preview_outcome}"
    )

    # the portal must observably be moving (not idle/untouched) right after the accepted
    # publish -- confirms the 202 above was real server-side work, not accepted-then-dropped.
    status_after = apigwv2.get_portal(PortalId=portal_id)["PublishStatus"]
    assert status_after in ("PUBLISH_IN_PROGRESS", "PUBLISHED"), (
        f"expected publish to be underway or done, got {status_after}"
    )


def _try_call(fn):
    try:
        resp = fn()
        return ("ok", resp["ResponseMetadata"]["HTTPStatusCode"])
    except ClientError as e:
        return ("error", e.response["Error"]["Code"])


def _custom_colors():
    return {
        "AccentColor": "#0000FF",
        "BackgroundColor": "#FFFFFF",
        "ErrorValidationColor": "#FF0000",
        "HeaderColor": "#111111",
        "NavigationColor": "#222222",
        "TextColor": "#000000",
    }


def _create_portal(ctx, teardown_deadline):
    apigwv2 = ctx.client("apigatewayv2")
    resp = apigwv2.create_portal(
        Authorization={"None": {}},
        EndpointConfiguration={"None": {}},
        PortalContent={
            "DisplayName": ctx.unique_name("sim2real-portal-"),
            "Theme": {"CustomColors": _custom_colors()},
        },
        Tags=TAGS,
    )
    portal_id = resp["PortalId"]
    ctx.on_cleanup(lambda: _disable_and_delete_portal(apigwv2, portal_id, teardown_deadline))
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

