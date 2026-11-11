"""start-auto-management-invalid-opt-in-level-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-auto-management-invalid-opt-in-level-rejected"
GROUP = "overly-permissive"
SERVICES = ["service-quotas"]


def _client_error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _safe_stop(ctx) -> None:
    sq = ctx.client("service-quotas")
    try:
        sq.stop_auto_management()
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchResourceException":
            raise


def _read_config(ctx):
    sq = ctx.client("service-quotas")
    try:
        cfg = sq.get_auto_management_configuration()
        return (cfg["OptInStatus"], cfg.get("OptInType"))
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchResourceException":
            return None
        raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:service-quotas-auto-management")
def run(ctx) -> None:
    """StartAutoManagement with an OptInLevel outside the enum (only ACCOUNT is valid) is refused with
    ValidationException and its exact message and leaves the configuration unchanged; the same call
    with ACCOUNT reaches ENABLED with NotifyOnly."""
    sq = ctx.client("service-quotas")
    ctx.on_cleanup(lambda: _safe_stop(ctx))

    baseline = _read_config(ctx)

    code, message = _client_error(
        lambda: sq.start_auto_management(OptInLevel="REGION", OptInType="NotifyOnly")
    )
    assert code == "ValidationException", (
        f"expected ValidationException for an OptInLevel outside the supported enum, got {code!r}"
    )
    expected = (
        "1 validation error detected: Value at 'optInLevel' failed to satisfy constraint: "
        "Member must satisfy enum value set: [ACCOUNT]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after_bad_call = _read_config(ctx)
    assert after_bad_call == baseline, (
        "the rejected call changed the Automatic Management configuration: "
        f"before={baseline} after={after_bad_call}"
    )

    # Positive control: the same call with a valid OptInLevel succeeds.
    sq.start_auto_management(OptInLevel="ACCOUNT", OptInType="NotifyOnly")
    enabled = _read_config(ctx)
    assert enabled == ("ENABLED", "NotifyOnly"), (
        f"expected the positive control to enable Automatic Management, got {enabled!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
