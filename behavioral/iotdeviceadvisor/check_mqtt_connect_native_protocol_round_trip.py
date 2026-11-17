"""mqtt-connect-native-protocol-round-trip."""
from __future__ import annotations

import json
import os
import ssl
import tempfile
import time

from behavioral_harness import tags

CHECK = "mqtt-connect-native-protocol-round-trip"
GROUP = "native-protocol"
SERVICES = ["iotdeviceadvisor"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:native", "plane:data", "resource:account-singleton:iotdeviceadvisor-suite-run")
def run(ctx) -> None:
    """Device Advisor accepts a real MQTT/TLS CONNECT made with the device's own certificate to the
    endpoint a suite run returns, and reports the MQTT_Connect test case as PASS, so a backend that
    only fakes control-plane responses fails."""
    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        raise AssertionError(
            "paho-mqtt is not installed in this environment; install `paho-mqtt` to "
            "enable the native MQTT round-trip check against the Device Advisor endpoint."
        )

    iot = ctx.client("iot")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    da = ctx.client("iotdeviceadvisor")
    account_id = sts.get_caller_identity()["Account"]

    # --- IoT thing + certificate + policy ---
    thing_name = ctx.unique_name("sim2real-behav-thing-")
    thing_arn = iot.create_thing(thingName=thing_name)["thingArn"]
    ctx.on_cleanup(_teardown(lambda: iot.delete_thing(thingName=thing_name), "ResourceNotFoundException"))

    cert = iot.create_keys_and_certificate(setAsActive=True)
    cert_arn = cert["certificateArn"]
    cert_id = cert["certificateId"]
    cert_pem = cert["certificatePem"]
    private_key = cert["keyPair"]["PrivateKey"]

    def _delete_cert():
        _teardown(lambda: iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE"), "ResourceNotFoundException")()
        _teardown(lambda: iot.delete_certificate(certificateId=cert_id, forceDelete=True), "ResourceNotFoundException")()

    ctx.on_cleanup(_delete_cert)

    iot.attach_thing_principal(thingName=thing_name, principal=cert_arn)
    ctx.on_cleanup(
        _teardown(lambda: iot.detach_thing_principal(thingName=thing_name, principal=cert_arn), "ResourceNotFoundException")
    )

    policy_name = ctx.unique_name("sim2real-behav-da-iotpolicy-")
    iot.create_policy(
        policyName=policy_name,
        policyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["iot:Connect", "iot:Publish", "iot:Subscribe", "iot:Receive", "iot:RetainPublish"],
                        "Resource": "*",
                    }
                ],
            }
        ),
        tags=[{"Key": "env", "Value": "sim2real"}],
    )
    ctx.on_cleanup(_teardown(lambda: iot.delete_policy(policyName=policy_name), "ResourceNotFoundException"))
    iot.attach_policy(policyName=policy_name, target=cert_arn)
    ctx.on_cleanup(
        _teardown(lambda: iot.detach_policy(policyName=policy_name, target=cert_arn), "ResourceNotFoundException")
    )

    # --- IAM device-permission role Device Advisor assumes ---
    role_name = ctx.unique_name("sim2real-behav-da-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "iotdeviceadvisor.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": f"arn:aws:iotdeviceadvisor:*:{account_id}:suitedefinition/*"},
                },
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "env", "Value": "sim2real"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AWSIoTFullAccess"
    )
    ctx.on_cleanup(
        _teardown(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AWSIoTFullAccess"),
            "NoSuchEntity",
        )
    )

    # --- Device Advisor suite definition + run ---
    root_group = json.dumps(
        {
            "configuration": {},
            "tests": [
                {
                    "name": "sim2real-mqtt-connect-group",
                    "configuration": {},
                    "tests": [
                        {
                            "name": "sim2real-mqtt-connect-case",
                            "configuration": {"EXECUTION_TIMEOUT": 180},
                            "test": {"id": "MQTT_Connect", "version": "0.0.0"},
                        }
                    ],
                }
            ],
        }
    )
    suite_name = ctx.unique_name("sim2real-behav-suite-")
    device = {"thingArn": thing_arn, "certificateArn": cert_arn}

    def _create_suite():
        return da.create_suite_definition(
            suiteDefinitionConfiguration={
                "suiteDefinitionName": suite_name,
                "rootGroup": root_group,
                "devicePermissionRoleArn": role_arn,
                "devices": [device],
                "protocol": "MqttV3_1_1",
                "intendedForQualification": False,
            },
            tags={"env": "sim2real"},
        )

    # A freshly created IAM role is not reliably assumable by Device Advisor yet --
    # retry the call that binds devicePermissionRoleArn against that condition rather
    # than sleeping a fixed duration and hoping propagation finished in time.
    created = _call_with_role_propagation_retry(_create_suite)
    suite_id = created["suiteDefinitionId"]
    ctx.on_cleanup(_teardown(lambda: da.delete_suite_definition(suiteDefinitionId=suite_id), "ResourceNotFoundException"))

    # parallelRun=True serves the run on the device-level endpoint the run returns.
    start_resp = _call_with_role_propagation_retry(
        lambda: da.start_suite_run(
            suiteDefinitionId=suite_id,
            suiteRunConfiguration={"primaryDevice": device, "parallelRun": True},
            tags={"env": "sim2real"},
        )
    )
    run_id = start_resp["suiteRunId"]
    ctx.on_cleanup(lambda: _stop_and_drain(da, suite_id, run_id))
    endpoint = start_resp["endpoint"]

    # Device Advisor only accepts the TLS connection while the run is RUNNING.
    _poll_until(
        lambda: da.get_suite_run(suiteDefinitionId=suite_id, suiteRunId=run_id)["status"],
        lambda s: s == "RUNNING",
        timeout_s=90.0,
    )

    # --- real MQTT/TLS round trip against the Device Advisor endpoint ---
    host, port = ctx.endpoint_host(endpoint, 8883)
    connected, detail = _mqtt_connect_with_retry(
        mqtt, host, port, thing_name, cert_pem, private_key, timeout_s=150.0, retry_delay_s=5.0
    )

    final = _poll_until(
        lambda: da.get_suite_run(suiteDefinitionId=suite_id, suiteRunId=run_id),
        lambda r: r["status"] not in ("PENDING", "RUNNING", "STOPPING"),
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert connected, (
        f"device never established an MQTT CONNECT against {host}:{port}: {detail}; "
        f"suite run ended {final['status']!r}, test result {final.get('testResult')!r}"
    )
    assert final["status"] == "PASS", (
        f"expected suite run status PASS, got {final['status']!r}, test result {final.get('testResult')!r}"
    )
    groups = final["testResult"]["groups"]
    case_status = groups[0]["tests"][0]["status"]
    assert case_status == "PASS", f"expected MQTT_Connect test case status PASS, got {case_status!r}"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises.

    A delete conflict right after its detach is retried until the detach propagates."""
    from botocore.exceptions import ClientError

    def run_undo() -> None:
        for attempt in range(10):
            try:
                undo()
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code in not_found:
                    return
                if code not in ("DeleteConflictException", "DeleteConflict") or attempt == 9:
                    raise
            time.sleep(3)

    return run_undo


def _stop_and_drain(da, suite_id, run_id) -> None:
    """Stop the run unless it already ended, then wait for a terminal status."""
    from botocore.exceptions import ClientError

    terminal = ("PASS", "FAIL", "CANCELED", "STOPPED", "ERROR", "PASS_WITH_WARNINGS")
    status = da.get_suite_run(suiteDefinitionId=suite_id, suiteRunId=run_id)["status"]
    if status not in terminal:
        try:
            da.stop_suite_run(suiteDefinitionId=suite_id, suiteRunId=run_id)
        except ClientError as exc:
            # The run can end or start stopping between the read and the stop; anything else is a failed stop.
            if exc.response["Error"]["Code"] != "ValidationException":
                raise
            after = da.get_suite_run(suiteDefinitionId=suite_id, suiteRunId=run_id)["status"]
            if after not in terminal and after != "STOPPING":
                raise
    _poll_until(
        lambda: da.get_suite_run(suiteDefinitionId=suite_id, suiteRunId=run_id)["status"],
        lambda s: s in terminal,
        timeout_s=300.0,
        interval_s=5.0,
    )


def _call_with_role_propagation_retry(fn, *, attempts: int = 10, interval_s: float = 9.0):
    from botocore.exceptions import ClientError

    last_err = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in ("ValidationException", "InternalServerException"):
                raise
            last_err = err
            if attempt + 1 < attempts:
                time.sleep(interval_s)
    assert last_err is not None
    raise last_err


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


def _mqtt_connect_with_retry(mqtt, host, port, client_id, cert_pem, private_key, timeout_s=150.0, retry_delay_s=5.0):
    # The device's IoT certificate/policy just became active and Device Advisor's
    # own broker takes a similar propagation lag to honor it -- retry across a
    # bounded deadline rather than a fixed attempt count, and surface the last
    # concrete failure instead of a bare False.
    with tempfile.NamedTemporaryFile(mode="w", suffix=".crt", delete=False) as cert_file, \
            tempfile.NamedTemporaryFile(mode="w", suffix=".key", delete=False) as key_file:
        cert_file.write(cert_pem)
        key_file.write(private_key)
        cert_path = cert_file.name
        key_path = key_file.name

    last_detail = "no attempt completed"
    deadline = time.monotonic() + timeout_s
    try:
        while time.monotonic() < deadline:
            state = {"connected": False, "rc": None}

            def _on_connect(client, userdata, flags, rc):
                state["connected"] = rc == 0
                state["rc"] = rc

            client = mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv311)
            client.on_connect = _on_connect
            client.tls_set(certfile=cert_path, keyfile=key_path, cert_reqs=ssl.CERT_NONE)
            try:
                client.connect(host, port=port, keepalive=30)
                client.loop_start()
                attempt_deadline = time.monotonic() + 10.0
                while time.monotonic() < attempt_deadline and not state["connected"]:
                    time.sleep(0.5)
                client.disconnect()
                client.loop_stop()
                if state["connected"]:
                    return True, None
                last_detail = f"CONNACK rc={state['rc']!r}" if state["rc"] is not None else "no CONNACK within 10s"
            except (OSError, ConnectionError) as exc:
                last_detail = f"{type(exc).__name__}: {exc}"
            time.sleep(retry_delay_s)
        return False, last_detail
    finally:
        os.unlink(cert_path)
        os.unlink(key_path)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
