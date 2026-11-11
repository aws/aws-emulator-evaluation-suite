"""update-scheduled-action-conflicting-window-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "update-scheduled-action-conflicting-window-rejected"
GROUP = "negative-classes"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateScheduledAction with ScheduleAt=TIMESTAMP and no DesiredStartTime fails
    ValidationException (an unknown ActionID with NOW fails ResourceNotFoundException) and leaves
    the scheduled action list unchanged; an existing action reschedules to NOW."""
    client = ctx.client("opensearch")
    domain_name = _domain_name(ctx, "sch")
    _create_minimal_domain(ctx, client, domain_name)
    _wait_domain_active(ctx, client, domain_name)

    baseline = client.list_scheduled_actions(DomainName=domain_name)["ScheduledActions"]
    assert isinstance(baseline, list)

    # Public APIs cannot create a colliding mandatory action, so no window conflict is exercised.
    bogus_action_id = ctx.unique_name("sim2real-bogus-action-")

    def _well_formed() -> None:
        client.update_scheduled_action(
            DomainName=domain_name,
            ActionID=bogus_action_id,
            ActionType="SERVICE_SOFTWARE_UPDATE",
            ScheduleAt="NOW",
        )

    control_code, control_message = _error_code(_well_formed)
    assert control_code == "ResourceNotFoundException", (
        f"expected the well-formed sibling request (same nonexistent ActionID) to fail "
        f"ResourceNotFoundException, got {control_code!r}"
    )
    expected = "ReleaseVersion does not applies for this domain or release does not exist"
    assert control_message == expected, f"expected message {expected!r}, got {control_message!r}"

    def _break() -> None:
        client.update_scheduled_action(
            DomainName=domain_name,
            ActionID=bogus_action_id,
            ActionType="SERVICE_SOFTWARE_UPDATE",
            ScheduleAt="TIMESTAMP",
            # DesiredStartTime deliberately omitted: required whenever
            # ScheduleAt=TIMESTAMP, per the API doc.
        )

    code, message = _error_code(_break)
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "Please provide the desired start time to schedule for a specific time."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    assert code != control_code, (
        "the malformed request must fail differently than its well-formed sibling, or the "
        "ValidationException above cannot be distinguished from a blanket ActionID rejection"
    )

    # Effect absent: the rejected call did not create or mutate any scheduled action.
    after = client.list_scheduled_actions(DomainName=domain_name)["ScheduledActions"]
    assert not any(a["Id"] == bogus_action_id for a in after)
    assert len(after) == len(baseline)

    # Bonus positive control, only if Auto-Tune already proposed a real action:
    # a fully valid reschedule of that REAL action must actually succeed and move it.
    if baseline:
        real_action = baseline[0]
        result = client.update_scheduled_action(
            DomainName=domain_name,
            ActionID=real_action["Id"],
            ActionType=real_action["Type"],
            ScheduleAt="NOW",
        )["ScheduledAction"]
        assert result["Id"] == real_action["Id"]
        assert result["Status"] in ("PENDING_UPDATE", "IN_PROGRESS", "COMPLETED")


def _domain_name(ctx: Any, tag: str) -> str:
    return ctx.unique_name(f"sim2real-{tag}-")[:28].rstrip("-")


def _create_minimal_domain(ctx: Any, client: Any, domain_name: str) -> None:
    client.create_domain(
        DomainName=domain_name,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        # AutoTuneOptions omitted: CreateDomain rejects Auto-Tune ENABLED on t2/t3 instance
        # types with ValidationException.
        TagList=[{"Key": "sim2real", "Value": domain_name}],
    )
    ctx.on_cleanup(lambda: _delete_domain_and_wait(ctx, client, domain_name))


def _delete_domain_and_wait(ctx: Any, client: Any, domain_name: str) -> None:
    try:
        client.delete_domain(DomainName=domain_name)
    except Exception as exc:
        if _error_code_from_exc(exc) != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + 1200
    while time.monotonic() < deadline:
        try:
            client.describe_domain(DomainName=domain_name)
        except Exception as exc:
            code = _error_code_from_exc(exc)
            if code == "ResourceNotFoundException":
                return
            # DescribeDomain throttles under the suite's concurrent polls: poll again.
            if code != "ThrottlingException":
                raise
        time.sleep(20)


def _wait_domain_active(ctx: Any, client: Any, domain_name: str, timeout_s: float = 1200.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            status = client.describe_domain(DomainName=domain_name)["DomainStatus"]
        except Exception as exc:  # noqa: BLE001
            # DescribeDomain throttles under the suite's concurrent polls: poll again to the deadline.
            if _error_code_from_exc(exc) != "ThrottlingException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
            continue
        last = status
        if status.get("Created") and not status.get("Processing") and status.get("Endpoint"):
            return status
        time.sleep(2)
    raise AssertionError(f"domain {domain_name} never became active: {last}")


def _error_code_from_exc(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if not response:
        return None
    return response.get("Error", {}).get("Code")


def _error_code(fn) -> tuple[str | None, str | None]:
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None) or {}
        return _error_code_from_exc(exc), response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
