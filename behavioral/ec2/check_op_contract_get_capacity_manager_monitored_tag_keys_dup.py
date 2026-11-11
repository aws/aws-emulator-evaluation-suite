"""op-contract-get-capacity-manager-monitored-tag-keys-dup."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-capacity-manager-monitored-tag-keys-dup"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-capacity-manager")
def run(ctx) -> None:
    """GetCapacityManagerMonitoredTagKeys, with Capacity Manager enabled, returns a
    CapacityManagerTagKeys list whose items carry TagKey and Status; DryRun fails with
    DryRunOperation and the standard message."""
    ec2 = ctx.client("ec2")

    try:
        attrs = ec2.get_capacity_manager_attributes()
        enabled = attrs["CapacityManagerStatus"] == "enabled"
    except ClientError as exc:
        if _code(exc) != "CapacityManager.Disabled":
            raise
        enabled = False

    if not enabled:
        _enable_capacity_manager(ec2)
        ctx.on_cleanup(lambda: _best_effort_disable(ec2))
        _poll_until(
            lambda: ec2.get_capacity_manager_attributes()["CapacityManagerStatus"],
            lambda status: status == "enabled",
            timeout_s=120,
        )

    resp = ec2.get_capacity_manager_monitored_tag_keys()
    assert "CapacityManagerTagKeys" in resp, f"response missing CapacityManagerTagKeys: {sorted(resp)}"
    assert isinstance(resp["CapacityManagerTagKeys"], list)
    for item in resp["CapacityManagerTagKeys"]:
        assert "TagKey" in item, item
        assert "Status" in item, item

    code, message = _error(lambda: ec2.get_capacity_manager_monitored_tag_keys(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"


def _code(exc: ClientError) -> str | None:
    return exc.response.get("Error", {}).get("Code")


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _best_effort_disable(ec2) -> None:
    ec2.disable_capacity_manager()


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


def _enable_capacity_manager(ec2, timeout_s=120.0, interval_s=5.0) -> None:
    """EnableCapacityManager, waiting out a disable still in progress: AWS refuses a second
    mutation with ConcurrentMutationLimitExceeded until the first one settles."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.enable_capacity_manager(OrganizationsAccess=False)
            return
        except ClientError as exc:
            if _code(exc) != "ConcurrentMutationLimitExceeded" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
