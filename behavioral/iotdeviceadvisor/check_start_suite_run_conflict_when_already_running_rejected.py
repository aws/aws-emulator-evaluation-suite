"""start-suite-run-conflict-when-already-running-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-suite-run-conflict-when-already-running-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotdeviceadvisor"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:iotdeviceadvisor-suite-run")
def run(ctx) -> None:
    """Starting a second run for the same suite/device while one is already in progress
    is rejected with ConflictException; once the first run is stopped, starting a new one
    succeeds normally."""
    da = ctx.client("iotdeviceadvisor")
    suite_id, device = _create_run_ready_suite(ctx, execution_timeout=120)

    run1 = da.start_suite_run(suiteDefinitionId=suite_id, suiteRunConfiguration={"primaryDevice": device})
    run1_id = run1["suiteRunId"]
    ctx.on_cleanup(lambda: _tolerant_stop(da, suite_id, run1_id))

    def _attempt():
        da.start_suite_run(suiteDefinitionId=suite_id, suiteRunConfiguration={"primaryDevice": device})

    code, message = _error(_attempt)
    assert code == "ConflictException", f"expected ConflictException while run1 is active, got {code!r}"
    expected_message = (
        "Suite already running with this account. Please stop suite run or wait until the suite "
        "finishes running. You can also use device-level endpoint to run suites in parallel."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: only run1 shows up for this suite -- the rejected attempt created nothing
    listed = da.list_suite_runs(suiteDefinitionId=suite_id)["suiteRunsList"]
    run_ids = [r["suiteRunId"] for r in listed]
    assert run_ids == [run1_id], f"expected only run1 ({run1_id}) listed, got {run_ids}"

    # stop run1 and poll it to its terminal STOPPED state
    da.stop_suite_run(suiteDefinitionId=suite_id, suiteRunId=run1_id)
    run1_status = _poll_until(
        lambda: da.get_suite_run(suiteDefinitionId=suite_id, suiteRunId=run1_id)["status"],
        lambda s: s not in ("PENDING", "RUNNING", "STOPPING"),
        timeout_s=_capped(ctx, 280.0),
        interval_s=5.0,
    )
    assert run1_status == "STOPPED", f"expected run1 to reach STOPPED after StopSuiteRun, got {run1_status!r}"

    # positive control: once run1 is done, a new run for the same suite/device succeeds
    run2 = da.start_suite_run(suiteDefinitionId=suite_id, suiteRunConfiguration={"primaryDevice": device})
    run2_id = run2["suiteRunId"]
    assert run2_id != run1_id, f"expected a fresh run id, got run1's id {run1_id} again"
    ctx.on_cleanup(lambda: _tolerant_stop(da, suite_id, run2_id))

    # read independent of the mutating StartSuiteRun call: GetSuiteRun confirms run2 is
    # genuinely live at the destination, not just echoed back in the start response
    run2_state = da.get_suite_run(suiteDefinitionId=suite_id, suiteRunId=run2_id)
    assert run2_state["suiteRunId"] == run2_id, (
        f"expected GetSuiteRun to report {run2_id}, got {run2_state.get('suiteRunId')!r}"
    )
    assert run2_state["status"] in ("PENDING", "RUNNING"), (
        f"expected run2 status PENDING/RUNNING right after start, got {run2_state.get('status')!r}"
    )

    # then stop it and poll GetSuiteRun to its terminal STOPPED state, which only a run that
    # was genuinely started can reach
    da.stop_suite_run(suiteDefinitionId=suite_id, suiteRunId=run2_id)
    run2_status = _poll_until(
        lambda: da.get_suite_run(suiteDefinitionId=suite_id, suiteRunId=run2_id)["status"],
        lambda s: s not in ("PENDING", "RUNNING", "STOPPING"),
        timeout_s=_capped(ctx, 420.0),
        interval_s=10.0,
    )
    assert run2_status == "STOPPED", f"expected run2 to reach STOPPED after StopSuiteRun, got {run2_status!r}"


# ===== helpers =====
def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, so a target
    that accepts what AWS refuses fails loudly rather than as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _dummy_role_arn(ctx) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:iam::{account_id}:role/sim2real-behav-nonexistent-role"


def _minimal_root_group(execution_timeout: int) -> str:
    return json.dumps(
        {
            "configuration": {},
            "tests": [
                {
                    "name": "sim2real-group",
                    "configuration": {},
                    "tests": [
                        {
                            "name": "sim2real-mqtt-connect",
                            "configuration": {"EXECUTION_TIMEOUT": execution_timeout},
                            "test": {"id": "MQTT_Connect", "version": "0.0.0"},
                        }
                    ],
                }
            ],
        }
    )


def _create_run_ready_suite(ctx, execution_timeout: int = 120):
    da = ctx.client("iotdeviceadvisor")
    iot = ctx.client("iot")
    thing_name = ctx.unique_name("sim2real-behav-thing-")
    thing_arn = iot.create_thing(thingName=thing_name)["thingArn"]
    ctx.on_cleanup(lambda: _tolerant_delete_thing(iot, thing_name))

    cert = iot.create_keys_and_certificate(setAsActive=True)
    cert_arn = cert["certificateArn"]
    cert_id = cert["certificateId"]
    iot.attach_thing_principal(thingName=thing_name, principal=cert_arn)
    ctx.on_cleanup(lambda: _tolerant_detach_and_delete_cert(iot, thing_name, cert_arn, cert_id))

    role_arn = _dummy_role_arn(ctx)
    name = ctx.unique_name("sim2real-behav-suite-")

    resp = da.create_suite_definition(
        suiteDefinitionConfiguration={
            "suiteDefinitionName": name,
            "rootGroup": _minimal_root_group(execution_timeout),
            "devicePermissionRoleArn": role_arn,
            "devices": [{"thingArn": thing_arn, "certificateArn": cert_arn}],
            "protocol": "MqttV3_1_1",
            "intendedForQualification": False,
        }
    )
    suite_id = resp["suiteDefinitionId"]
    ctx.on_cleanup(lambda: _tolerant_delete_suite(da, suite_id))
    return suite_id, {"thingArn": thing_arn, "certificateArn": cert_arn}


def _tolerant_delete_thing(iot, thing_name) -> None:
    from botocore.exceptions import ClientError

    try:
        iot.delete_thing(thingName=thing_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _tolerant_detach_and_delete_cert(iot, thing_name, cert_arn, cert_id) -> None:
    from botocore.exceptions import ClientError

    try:
        iot.detach_thing_principal(thingName=thing_name, principal=cert_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_certificate(certificateId=cert_id, forceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _tolerant_delete_suite(da, suite_id) -> None:
    from botocore.exceptions import ClientError

    try:
        da.delete_suite_definition(suiteDefinitionId=suite_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _tolerant_stop(da, suite_id, run_id) -> None:
    from botocore.exceptions import ClientError

    # a run that already ended refuses StopSuiteRun, so only a live run is stopped
    try:
        status = da.get_suite_run(suiteDefinitionId=suite_id, suiteRunId=run_id)["status"]
        if status in ("PENDING", "RUNNING"):
            da.stop_suite_run(suiteDefinitionId=suite_id, suiteRunId=run_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return

    # Device Advisor allows only ONE active suite run per account at a time -- drain
    # this run to a terminal state during cleanup so it doesn't block the NEXT check's
    # StartSuiteRun with ConflictException("Suite already running with this account").
    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline:
        try:
            status = da.get_suite_run(suiteDefinitionId=suite_id, suiteRunId=run_id)["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if status not in ("PENDING", "RUNNING", "STOPPING"):
            return
        time.sleep(5.0)


def _capped(ctx, budget_s: float) -> float:
    """The wait bound, capped by the run's remaining time so a wait fails with its own message."""
    left = ctx.time_left()
    return budget_s if left is None else max(1.0, min(budget_s, left - 5.0))


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
