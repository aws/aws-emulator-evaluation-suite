"""stop-suite-run-repeat-after-completion-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stop-suite-run-repeat-after-completion-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotdeviceadvisor"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:iotdeviceadvisor-suite-run")
def run(ctx) -> None:
    """Stopping a run that has already fully stopped is rejected as ValidationException
    (not a stoppable state), while stopping a fresh run still succeeds."""
    da = ctx.client("iotdeviceadvisor")
    suite_id, device = _create_run_ready_suite(ctx, execution_timeout=300)

    run1 = da.start_suite_run(suiteDefinitionId=suite_id, suiteRunConfiguration={"primaryDevice": device})
    run1_id = run1["suiteRunId"]
    ctx.on_cleanup(lambda: _tolerant_stop(da, suite_id, run1_id))

    _poll_until(
        lambda: da.get_suite_run(suiteDefinitionId=suite_id, suiteRunId=run1_id)["status"],
        lambda s: s == "RUNNING",
        timeout_s=60.0,
    )
    da.stop_suite_run(suiteDefinitionId=suite_id, suiteRunId=run1_id)

    # Per the AWS docs, "the cleanup process can take several minutes" before the
    # status reaches STOPPED -- poll for that documented (if slow) window.
    final_status = _poll_until(
        lambda: da.get_suite_run(suiteDefinitionId=suite_id, suiteRunId=run1_id)["status"],
        lambda s: s == "STOPPED",
        timeout_s=420.0,
        interval_s=10.0,
    )
    assert final_status == "STOPPED", f"expected run1 to reach STOPPED, got {final_status!r}"

    def _attempt():
        da.stop_suite_run(suiteDefinitionId=suite_id, suiteRunId=run1_id)

    code, message = _error(_attempt)
    assert code == "ValidationException", (
        f"expected repeat StopSuiteRun on an already-STOPPED run to raise ValidationException, "
        f"got {code!r}"
    )
    expected_message = f"Invalid Request: Suite run {run1_id} is not running and cannot be stopped"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the rejected repeat stop did not change the run's terminal state
    unchanged = da.get_suite_run(suiteDefinitionId=suite_id, suiteRunId=run1_id)["status"]
    assert unchanged == "STOPPED", (
        f"expected the rejected repeat stop to leave run1 unchanged at STOPPED, got {unchanged!r}"
    )

    # positive control: stopping a fresh, still-active run succeeds without error
    run2 = da.start_suite_run(suiteDefinitionId=suite_id, suiteRunConfiguration={"primaryDevice": device})
    run2_id = run2["suiteRunId"]
    ctx.on_cleanup(lambda: _tolerant_stop(da, suite_id, run2_id))
    _poll_until(
        lambda: da.get_suite_run(suiteDefinitionId=suite_id, suiteRunId=run2_id)["status"],
        lambda s: s == "RUNNING",
        timeout_s=60.0,
    )
    da.stop_suite_run(suiteDefinitionId=suite_id, suiteRunId=run2_id)
    status2 = _poll_until(
        lambda: da.get_suite_run(suiteDefinitionId=suite_id, suiteRunId=run2_id)["status"],
        lambda s: s not in ("PENDING", "RUNNING", "STOPPING"),
        timeout_s=420.0,
        interval_s=10.0,
    )
    assert status2 == "STOPPED", f"expected the fresh run2 to accept StopSuiteRun and reach STOPPED, got {status2!r}"


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
        },
        tags={"env": "sim2real", "purpose": "behavioral-check"},
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

    try:
        da.stop_suite_run(suiteDefinitionId=suite_id, suiteRunId=run_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

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
