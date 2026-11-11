"""portal-publish-server-managed-build."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "portal-publish-server-managed-build"
GROUP = "server-side"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PublishPortal reaches PUBLISHED with no further calls, reading only PUBLISH_IN_PROGRESS on
    the way, and the build provisions a default domain and sets LastPublished no earlier than this
    publish."""
    apigwv2 = ctx.client("apigatewayv2")
    portal_id = _create_portal(ctx)

    publish_issued_at = datetime.now(timezone.utc)
    apigwv2.publish_portal(PortalId=portal_id)

    terminal = None
    deadline = time.monotonic() + 600
    interval = 1.0
    while time.monotonic() < deadline:
        portal = apigwv2.get_portal(PortalId=portal_id)
        status = portal["PublishStatus"]
        if status in ("PUBLISHED", "PUBLISH_FAILED"):
            terminal = portal
            break
        assert status == "PUBLISH_IN_PROGRESS", f"unexpected intermediate publish status {status!r}"
        time.sleep(interval)
        interval = min(interval * 1.5, 15)

    assert terminal is not None, "portal publish never reached a terminal status within 600s"
    terminal_status = terminal["PublishStatus"]
    assert terminal_status == "PUBLISHED", f"portal publish did not reach PUBLISHED (last={terminal_status})"

    default_domain = (terminal.get("EndpointConfiguration") or {}).get("PortalDefaultDomainName")
    assert default_domain, (
        "a PUBLISHED portal must have a server-provisioned PortalDefaultDomainName; "
        f"got EndpointConfiguration={terminal.get('EndpointConfiguration')!r}"
    )

    last_published = terminal.get("LastPublished")
    assert last_published is not None, "a PUBLISHED portal must report LastPublished"
    assert last_published >= publish_issued_at - timedelta(seconds=5), (
        f"LastPublished ({last_published}) predates this run's own PublishPortal call "
        f"({publish_issued_at}) -- stale or fabricated build metadata"
    )



def _create_portal(ctx):
    apigwv2 = ctx.client("apigatewayv2")
    resp = apigwv2.create_portal(
        Authorization={"None": {}},
        EndpointConfiguration={"None": {}},
        PortalContent={
            "DisplayName": ctx.unique_name("sim2real-portal-"),
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
        Tags={"sim2real": CHECK},
    )
    portal_id = resp["PortalId"]
    ctx.on_cleanup(lambda: _cleanup_portal(ctx, apigwv2, portal_id))
    return portal_id


def _cleanup_portal(ctx, apigwv2, portal_id):
    try:
        apigwv2.delete_portal(PortalId=portal_id)
        return
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "NotFoundException":
            return
        if code not in ("ConflictException", "BadRequestException"):
            raise
    try:
        apigwv2.disable_portal(PortalId=portal_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        try:
            status = apigwv2.get_portal(PortalId=portal_id)["PublishStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
            return
        if status in ("DISABLED", "DISABLE_FAILED"):
            break
        time.sleep(2)
    try:
        apigwv2.delete_portal(PortalId=portal_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
