"""suite-run-without-device-fails-on-connect-timeout."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "suite-run-without-device-fails-on-connect-timeout"
GROUP = "state"
SERVICES = ["iotdeviceadvisor"]


# timing:real-time — workflow: 120 s
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:iotdeviceadvisor-suite-run", "timing:real-time")
def run(ctx) -> None:
    """A run whose device never connects times out the MQTT_Connect test case and ends FAIL."""
    da = ctx.client("iotdeviceadvisor")
    suite_id, device = _create_run_ready_suite(ctx, execution_timeout=120)

    start_resp = da.start_suite_run(
        suiteDefinitionId=suite_id,
        suiteRunConfiguration={"primaryDevice": device},
    )
    run_id = start_resp["suiteRunId"]
    ctx.on_cleanup(lambda: _tolerant_stop(da, suite_id, run_id))

    # Nothing ever connects to the Device Advisor endpoint for this thing, so the
    # MQTT_Connect test case must time out (EXECUTION_TIMEOUT=120s) and the run
    # must reach a terminal, failed state on its own.
    final = _poll_until(
        lambda: da.get_suite_run(suiteDefinitionId=suite_id, suiteRunId=run_id),
        lambda r: r["status"] not in ("PENDING", "RUNNING", "STOPPING"),
        timeout_s=280.0,
        interval_s=5.0,
    )
    assert final["status"] == "FAIL", f"expected suite run status FAIL, got {final['status']!r}"
    assert final.get("endTime") is not None, "expected a terminal run to carry an endTime"

    groups = final.get("testResult", {}).get("groups", [])
    assert groups, "expected at least one test group result"
    tests = groups[0].get("tests", [])
    assert tests, "expected at least one test case result"
    assert tests[0]["status"] == "FAIL", (
        f"expected the MQTT_Connect test case to FAIL on timeout, got {tests[0]['status']!r}"
    )


# ===== helpers =====
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
