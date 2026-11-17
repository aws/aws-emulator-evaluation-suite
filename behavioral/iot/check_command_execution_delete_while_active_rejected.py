"""command-execution-delete-while-active-rejected."""
from __future__ import annotations

import json
import os
import ssl
import tempfile
import threading
import time

import botocore.exceptions

from behavioral_harness import tags

CHECK = "command-execution-delete-while-active-rejected"
GROUP = "overly-permissive"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "dp:native", "plane:data")
def run(ctx) -> None:
    """DeleteCommandExecution on a non-terminal execution fails with ValidationException and
    its exact message and leaves it retrievable; after a device reports SUCCEEDED over MQTT the
    delete succeeds and Get fails with ResourceNotFoundException."""
    import paho.mqtt.client as mqtt  # noqa: F401
    iot = ctx.client("iot")

    thing_name = ctx.unique_name("sim2real-cmdconflict-thing-")
    thing_arn = iot.create_thing(thingName=thing_name)["thingArn"]
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    keys_cert = iot.create_keys_and_certificate(setAsActive=True)
    cert_id = keys_cert["certificateId"]
    cert_arn = keys_cert["certificateArn"]
    ctx.on_cleanup(lambda: _cleanup_cert(iot, cert_id))

    policy_name = ctx.unique_name("sim2real-cmdconflict-policy-")
    iot.create_policy(
        policyName=policy_name,
        policyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["iot:Connect", "iot:Subscribe", "iot:Receive", "iot:Publish"], "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iot.delete_policy(policyName=policy_name))
    iot.attach_policy(policyName=policy_name, target=cert_arn)
    ctx.on_cleanup(lambda: iot.detach_policy(policyName=policy_name, target=cert_arn))
    iot.attach_thing_principal(thingName=thing_name, principal=cert_arn)
    ctx.on_cleanup(lambda: iot.detach_thing_principal(thingName=thing_name, principal=cert_arn))

    command_id = ctx.unique_name("sim2real-cmdconflict-")
    command_arn = iot.create_command(
        commandId=command_id,
        namespace="AWS-IoT",
        payload={"content": b'{"action": "noop"}', "contentType": "application/json"},
    )["commandArn"]
    ctx.on_cleanup(lambda: iot.delete_command(commandId=command_id))

    # Commands data-plane calls go to the iot:Data-ATS endpoint; the iot:Jobs endpoint type is
    # refused for them.
    jobs_endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    jobs_data = ctx.client("iot-jobs-data", endpoint_url=ctx.endpoint_url(jobs_endpoint))
    execution_id = jobs_data.start_command_execution(
        commandArn=command_arn, targetArn=thing_arn, executionTimeoutSeconds=60
    )["executionId"]

    code, message = _error_code(
        lambda: iot.delete_command_execution(executionId=execution_id, targetArn=thing_arn)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "Failed to delete command execution as it hasn't become terminal."
    assert message == expected, f"DeleteCommandExecution message {message!r} != {expected!r}"

    # Effect absent: the execution must still be retrievable -- it was NOT deleted.
    still_there = iot.get_command_execution(executionId=execution_id, targetArn=thing_arn)
    assert still_there["executionId"] == execution_id, (
        f"expected the rejected delete to leave {execution_id!r} retrievable, "
        f"got executionId={still_there['executionId']!r}"
    )
    assert still_there["status"] in ("CREATED", "IN_PROGRESS"), (
        f"expected the non-terminal execution to remain CREATED/IN_PROGRESS after the "
        f"rejected delete, got status={still_there['status']!r}"
    )

    # Positive control, same file: connect a real device over MQTT and have it report
    # SUCCEEDED over the reserved commands response topic, driving a genuine terminal-state
    # transition. The identical delete call then succeeds.
    tmp_dir = tempfile.mkdtemp(prefix="sim2real-iot-cmdconflict-")
    ctx.on_cleanup(lambda: _rmtree(tmp_dir))
    cert_path = os.path.join(tmp_dir, "device-cert.pem")
    key_path = os.path.join(tmp_dir, "device-key.pem")
    with open(cert_path, "wb") as f:
        f.write(keys_cert["certificatePem"].encode())
    with open(key_path, "wb") as f:
        f.write(keys_cert["keyPair"]["PrivateKey"].encode())

    client = _make_mqtt_client(thing_name)
    _mqtt_connect(client, *ctx.endpoint_host(jobs_endpoint, 8883), cert_path, key_path)
    try:
        response_topic = f"$aws/commands/things/{thing_name}/executions/{execution_id}/response/json"
        client.publish(response_topic, json.dumps({"status": "SUCCEEDED"}), qos=1)
    finally:
        try:
            client.loop_stop()
            client.disconnect()
        except Exception:  # noqa: BLE001
            pass

    _poll_until(
        lambda: iot.get_command_execution(executionId=execution_id, targetArn=thing_arn),
        lambda resp: resp["status"] == "SUCCEEDED",
        timeout_s=30,
        interval_s=2,
    )
    iot.delete_command_execution(executionId=execution_id, targetArn=thing_arn)
    not_found_code, not_found_message = _error_code(
        lambda: iot.get_command_execution(executionId=execution_id, targetArn=thing_arn)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"expected the terminal execution's delete to leave {execution_id!r} gone, "
        f"got error code {not_found_code!r} from the post-delete read"
    )
    expected = f"Command execution {execution_id} cannot be found."
    assert not_found_message == expected, (
        f"GetCommandExecution message {not_found_message!r} != {expected!r}"
    )

    # A repeat delete of the already-deleted id is an idempotent success on AWS, and the
    # execution stays gone.
    iot.delete_command_execution(executionId=execution_id, targetArn=thing_arn)
    regone_code, regone_message = _error_code(
        lambda: iot.get_command_execution(executionId=execution_id, targetArn=thing_arn)
    )
    assert regone_code == "ResourceNotFoundException", (
        f"expected {execution_id!r} to stay gone after the repeat delete, got {regone_code!r}"
    )
    assert regone_message == expected, (
        f"GetCommandExecution message {regone_message!r} != {expected!r}"
    )


def _error_code(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (error code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _cleanup_cert(iot, cert_id: str) -> None:
    iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    iot.delete_certificate(certificateId=cert_id, forceDelete=True)


def _rmtree(path: str) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)


def _make_mqtt_client(client_id: str):
    import paho.mqtt.client as mqtt

    try:
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=client_id)
    except AttributeError:
        return mqtt.Client(client_id=client_id)


def _mqtt_connect(client, host: str, port: int, cert_path: str, key_path: str) -> None:
    """Connect with mutual TLS, encrypted without verifying the server's identity."""
    connected = threading.Event()
    rc_holder: dict = {}

    def on_connect(_c, _u, _f, rc):
        rc_holder["rc"] = rc
        if rc == 0:
            connected.set()

    client.on_connect = on_connect
    client.tls_set(cert_reqs=ssl.CERT_NONE, certfile=cert_path, keyfile=key_path)
    client.connect(host, port, keepalive=30)
    client.loop_start()
    if not connected.wait(timeout=20):
        client.loop_stop()
        raise AssertionError(f"MQTT connect to {host}:{port} timed out (rc={rc_holder.get('rc')})")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last value: {value!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


