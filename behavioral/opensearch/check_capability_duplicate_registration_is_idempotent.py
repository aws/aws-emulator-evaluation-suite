"""capability-duplicate-registration-is-idempotent."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "capability-duplicate-registration-is-idempotent"
GROUP = "state-machine"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-registering a settled capability with an identical config succeeds (no
    ResourceAlreadyExists or Conflict) and leaves it in the same terminal state, not a new cycle.
    """
    osv = ctx.client("opensearch")
    app_id = _create_application(ctx)

    osv.register_capability(
        applicationId=app_id,
        capabilityName="ai-capability",
        capabilityConfig={"aiConfig": {}},
    )
    ctx.on_cleanup(lambda: _safe_deregister(osv, app_id))

    status = _wait_capability_status(osv, app_id, "ai-capability", {"active", "create_failed"}, timeout_s=300)

    # The duplicate call itself must not raise.
    osv.register_capability(
        applicationId=app_id,
        capabilityName="ai-capability",
        capabilityConfig={"aiConfig": {}},
    )

    after = osv.get_capability(applicationId=app_id, capabilityName="ai-capability")["status"]
    assert after == status, (
        f"duplicate registration changed capability status from {status!r} to {after!r} "
        "(expected a true idempotent no-op)"
    )


# ===== shared domain helpers =====

def _create_application(ctx) -> str:
    osv = ctx.client("opensearch")
    name = ctx.unique_name("sim2real-app-")
    resp = osv.create_application(name=name)
    app_id = resp["id"]
    ctx.on_cleanup(lambda: _safe_delete_application(osv, app_id))
    _wait_application_active(osv, app_id, timeout_s=300)
    return app_id


def _wait_application_active(osv, app_id: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = osv.get_application(id=app_id)["status"]
        if last == "ACTIVE":
            return
        if last == "FAILED":
            raise AssertionError(f"application {app_id} entered FAILED state while waiting for ACTIVE")
        time.sleep(interval_s)
    raise AssertionError(f"application {app_id} did not reach ACTIVE within {timeout_s}s (last={last})")


def _wait_capability_status(osv, app_id: str, name: str, terminal: set[str], timeout_s: float = 300.0, interval_s: float = 5.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = osv.get_capability(applicationId=app_id, capabilityName=name)["status"]
        if last in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"capability {name} on {app_id} did not reach {terminal} within {timeout_s}s (last={last})")


def _teardown_call(fn, timeout_s: float = 300.0) -> None:
    """Run a teardown call: return on ResourceNotFoundException, retry ConflictException (a change
    still in progress) every 2 s to the deadline, raise anything else."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _safe_deregister(osv, app_id: str) -> None:
    _teardown_call(lambda: osv.deregister_capability(applicationId=app_id, capabilityName="ai-capability"))


def _safe_delete_application(osv, app_id: str) -> None:
    _teardown_call(lambda: osv.delete_application(id=app_id))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
