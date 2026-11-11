"""enable-capacity-manager-contract."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "enable-capacity-manager-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-capacity-manager")
def run(ctx) -> None:
    """EnableCapacityManager turns on Capacity Manager for the account with the requested
    OrganizationsAccess setting, and a DryRun call is rejected with DryRunOperation without
    changing the account's enablement status."""
    ec2 = ctx.client("ec2")

    def _best_effort_disable():
        ec2.disable_capacity_manager()

    # NEGATIVE: DryRun is rejected and must not enable anything -- checked against
    # an independent read taken before and after, so this holds whether the account
    # started disabled or was already enabled from a prior run.
    before_status = _status(ec2)
    if before_status != "enabled":
        ctx.on_cleanup(_best_effort_disable)
    code, message = _error(lambda: ec2.enable_capacity_manager(DryRun=True))
    assert code == "DryRunOperation", f"unexpected DryRun error code: {code!r}"
    assert message == DRY_RUN_MESSAGE, f"unexpected DryRun message: {message!r}"
    after_status = _status(ec2)
    assert after_status == before_status, (
        f"DryRun must not change Capacity Manager status: before={before_status!r} "
        f"after={after_status!r}"
    )

    # POSITIVE: the real call enables Capacity Manager and echoes the requested settings
    # in its own response.
    resp = ec2.enable_capacity_manager(OrganizationsAccess=False)
    assert resp["CapacityManagerStatus"] == "enabled", (
        f"expected CapacityManagerStatus='enabled' echoed back, got "
        f"{resp['CapacityManagerStatus']!r}"
    )
    assert resp["OrganizationsAccess"] is False, (
        f"expected OrganizationsAccess=False echoed back, got {resp['OrganizationsAccess']!r}"
    )

    # TERMINAL: an independent read -- GetCapacityManagerAttributes, never the Enable
    # response itself -- must agree. Account-level enablement propagation is
    # asynchronous, so poll with a bounded deadline rather than trusting a single read.
    attrs = _poll_until(
        lambda: ec2.get_capacity_manager_attributes(),
        lambda a: a["CapacityManagerStatus"] == "enabled",
        timeout_s=120,
    )
    assert attrs["OrganizationsAccess"] is False, (
        f"GetCapacityManagerAttributes should report OrganizationsAccess=False after "
        f"enabling with OrganizationsAccess=False, got {attrs['OrganizationsAccess']!r}"
    )


def _error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected success raises, because
    a target accepting what real AWS refuses must not read as a plain code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _status(ec2):
    """CapacityManagerStatus via an independent read, normalizing the
    CapacityManager.Disabled error (never-enabled account) to "disabled" so
    before/after comparisons work regardless of starting state."""
    from botocore.exceptions import ClientError

    try:
        return ec2.get_capacity_manager_attributes()["CapacityManagerStatus"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "CapacityManager.Disabled":
            return "disabled"
        raise


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
