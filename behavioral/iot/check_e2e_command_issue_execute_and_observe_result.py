"""e2e-command-issue-execute-and-observe-result."""
from __future__ import annotations

import json
import os
import ssl
import tempfile
import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-command-issue-execute-and-observe-result"
GROUP = "e2e"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c6", "concern:data-plane", "concern:eventing", "dp:native", "plane:data")
def run(ctx) -> None:
    """A started command execution is CREATED or IN_PROGRESS for its command, reaches SUCCEEDED
    once the device reports over MQTT, then reads ResourceNotFoundException after delete, and
    the deleted command shows pendingDeletion."""
    import paho.mqtt.client as mqtt  # noqa: F401
    iot = ctx.client("iot")
    scenario = "command-issue-execute-and-observe-result"

    thing_name = ctx.unique_name("sim2real-cmd-thing-")
    thing_arn = iot.create_thing(
        thingName=thing_name, attributePayload={"attributes": {"sim2real": scenario}}
    )["thingArn"]
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    keys_cert = iot.create_keys_and_certificate(setAsActive=True)
    cert_id = keys_cert["certificateId"]
    cert_arn = keys_cert["certificateArn"]
    ctx.on_cleanup(lambda: _cleanup_cert(iot, cert_id))

    policy_name = ctx.unique_name("sim2real-cmd-policy-")
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
        tags=[{"Key": "sim2real", "Value": scenario}],
    )
    ctx.on_cleanup(lambda: iot.delete_policy(policyName=policy_name))
    iot.attach_policy(policyName=policy_name, target=cert_arn)
    ctx.on_cleanup(lambda: iot.detach_policy(policyName=policy_name, target=cert_arn))
    iot.attach_thing_principal(thingName=thing_name, principal=cert_arn)
    ctx.on_cleanup(lambda: iot.detach_thing_principal(thingName=thing_name, principal=cert_arn))

    command_id = ctx.unique_name("sim2real-cmd-")
    command_arn = iot.create_command(
        commandId=command_id,
        namespace="AWS-IoT",
        payload={"content": b'{"action": "reboot"}', "contentType": "application/json"},
        tags=[{"Key": "sim2real", "Value": scenario}],
    )["commandArn"]
    ctx.on_cleanup(lambda: iot.delete_command(commandId=command_id))

    # Commands data-plane calls go to the iot:Data-ATS endpoint; the iot:Jobs endpoint type is
    # refused for them.
    jobs_endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    jobs_data = ctx.client("iot-jobs-data", endpoint_url=ctx.endpoint_url(jobs_endpoint))

    tmp_dir = tempfile.mkdtemp(prefix="sim2real-iot-cmd-")
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
        execution_id = jobs_data.start_command_execution(
            commandArn=command_arn, targetArn=thing_arn, executionTimeoutSeconds=60
        )["executionId"]
        ctx.on_cleanup(lambda: _cleanup_execution(iot, execution_id, thing_arn))

        described = iot.get_command_execution(executionId=execution_id, targetArn=thing_arn)
        assert described["status"] in (
            "CREATED",
            "IN_PROGRESS",
        ), f"expected a non-terminal status right after StartCommandExecution, got {described['status']!r}"
        assert described["commandArn"] == command_arn, (
            f"GetCommandExecution reported commandArn {described['commandArn']!r}, expected {command_arn!r}"
        )

        response_topic = f"$aws/commands/things/{thing_name}/executions/{execution_id}/response/json"
        client.publish(response_topic, json.dumps({"status": "SUCCEEDED"}), qos=1)
    finally:
        try:
            client.loop_stop()
            client.disconnect()
        except Exception:  # noqa: BLE001
            pass

    final = _poll_until(
        lambda: iot.get_command_execution(executionId=execution_id, targetArn=thing_arn),
        lambda resp: resp["status"] == "SUCCEEDED",
        timeout_s=30,
        interval_s=2,
    )
    assert final["status"] == "SUCCEEDED", f"execution ended in unexpected status {final['status']!r}"

    iot.delete_command_execution(executionId=execution_id, targetArn=thing_arn)
    try:
        iot.get_command_execution(executionId=execution_id, targetArn=thing_arn)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException after DeleteCommandExecution, got {err.get('Code')!r}"
        )
        expected = f"Command execution {execution_id} cannot be found."
        assert err.get("Message") == expected, (
            f"GetCommandExecution message {err.get('Message')!r} != {expected!r}"
        )
    else:
        raise AssertionError("command execution was still retrievable after DeleteCommandExecution")

    iot.delete_command(commandId=command_id)

    # DeleteCommand is a soft delete: the command stays readable with pendingDeletion=True and is
    # reaped asynchronously, so it must not be expected to vanish synchronously.
    def _command_gone_or_pending():
        try:
            return iot.get_command(commandId=command_id)
        except iot.exceptions.ResourceNotFoundException:
            return None

    final_command = _poll_until(
        _command_gone_or_pending,
        lambda r: r is None or r.get("pendingDeletion") is True,
        timeout_s=60,
        interval_s=2,
    )
    if final_command is not None:
        assert final_command["pendingDeletion"] is True, (
            f"a deleted command must report pendingDeletion=True, got {final_command.get('pendingDeletion')!r}"
        )


def _cleanup_cert(iot, cert_id: str) -> None:
    iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    iot.delete_certificate(certificateId=cert_id, forceDelete=True)


def _cleanup_execution(iot, execution_id: str, target_arn: str) -> None:
    try:
        iot.delete_command_execution(executionId=execution_id, targetArn=target_arn)
    except iot.exceptions.ResourceNotFoundException:
        pass


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


