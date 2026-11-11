"""auto-management-start-update-stop-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "auto-management-start-update-stop-lifecycle"
GROUP = "deploy"
SERVICES = ["service-quotas"]


def _safe_stop(ctx) -> None:
    sq = ctx.client("service-quotas")
    try:
        sq.stop_auto_management()
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchResourceException":
            raise


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:service-quotas-auto-management")
def run(ctx) -> None:
    """StartAutoManagement enables Automatic Management, UpdateAutoManagement
    changes its opt-in type without touching status, and StopAutoManagement
    disables it again -- a full account-level state machine round trip."""
    sq = ctx.client("service-quotas")
    ctx.on_cleanup(lambda: _safe_stop(ctx))

    sq.start_auto_management(OptInLevel="ACCOUNT", OptInType="NotifyOnly")
    cfg = sq.get_auto_management_configuration()
    assert cfg["OptInStatus"] == "ENABLED", f"expected ENABLED after start, got {cfg['OptInStatus']!r}"
    assert cfg["OptInType"] == "NotifyOnly", f"expected NotifyOnly after start, got {cfg['OptInType']!r}"

    sq.update_auto_management(OptInType="NotifyAndAdjust")
    cfg2 = sq.get_auto_management_configuration()
    assert cfg2["OptInType"] == "NotifyAndAdjust", (
        f"expected NotifyAndAdjust after update, got {cfg2['OptInType']!r}"
    )
    assert cfg2["OptInStatus"] == "ENABLED", (
        f"UpdateAutoManagement must not change OptInStatus, got {cfg2['OptInStatus']!r}"
    )

    sq.stop_auto_management()
    cfg3 = sq.get_auto_management_configuration()
    assert cfg3["OptInStatus"] == "DISABLED", f"expected DISABLED after stop, got {cfg3['OptInStatus']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
