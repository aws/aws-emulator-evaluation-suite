"""start-suite-run-creates-pending-or-running-run."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-suite-run-creates-pending-or-running-run"
GROUP = "state"
SERVICES = ["iotdeviceadvisor"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:iotdeviceadvisor-suite-run")
def run(ctx) -> None:
    """StartSuiteRun immediately creates a run visible via GetSuiteRun in PENDING or RUNNING."""
    da = ctx.client("iotdeviceadvisor")
    suite_id, device = _create_run_ready_suite(ctx, execution_timeout=120)

    start_resp = da.start_suite_run(
        suiteDefinitionId=suite_id,
        suiteRunConfiguration={"primaryDevice": device},
    )
    run_id = start_resp["suiteRunId"]
    assert start_resp["suiteRunArn"].endswith(run_id), (
        f"expected suiteRunArn to end with suiteRunId {run_id!r}, got {start_resp['suiteRunArn']!r}"
    )
    ctx.on_cleanup(lambda: _tolerant_stop(da, suite_id, run_id))

    got = da.get_suite_run(suiteDefinitionId=suite_id, suiteRunId=run_id)
    assert got["suiteRunId"] == run_id, f"expected suiteRunId {run_id!r}, got {got['suiteRunId']!r}"
    assert got["status"] in ("PENDING", "RUNNING"), (
        f"expected an immediate status of PENDING or RUNNING, got {got['status']!r}"
    )

    # A suite with one real test case configured must actually enter RUNNING, not skip straight from
    # PENDING to a terminal status (Device Advisor only accepts the device's MQTT CONNECT while a
    # run is RUNNING, so a target that never reports RUNNING has no window in which a real device
    # could ever pass).
    status = _poll_until(
        lambda: da.get_suite_run(suiteDefinitionId=suite_id, suiteRunId=run_id)["status"],
        lambda s: s == "RUNNING",
        timeout_s=90.0,
    )
    assert status == "RUNNING", f"expected the run to reach RUNNING within 90s, got {status!r}"


# ===== helpers =====
import json


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
