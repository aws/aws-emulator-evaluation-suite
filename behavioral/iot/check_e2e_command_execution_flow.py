"""e2e-command-execution-flow."""
from __future__ import annotations

import json
import queue
import ssl
import tempfile
import threading
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-command-execution-flow"
GROUP = "e2e"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c4", "cap:c6", "concern:data-plane", "concern:eventing", "dp:native", "plane:data")
def run(ctx) -> None:
    """A command execution reaches SUCCEEDED only after a device reports it over the
    reserved MQTT commands topics; it is listed, and after DeleteCommandExecution Get
    fails with ResourceNotFoundException and its exact message."""
    import paho.mqtt.client as mqtt

    iot = ctx.client("iot")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    jobs_data = ctx.client("iot-jobs-data", endpoint_url=ctx.endpoint_url(endpoint))

    thing_name = ctx.unique_name("sim2real-cmd-thing-")
    iot.create_thing(thingName=thing_name)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))
    thing_arn = iot.describe_thing(thingName=thing_name)["thingArn"]

    cert = iot.create_keys_and_certificate(setAsActive=True)
    cert_id = cert["certificateId"]
    cert_arn = cert["certificateArn"]
    ctx.on_cleanup(lambda: _retire_certificate(iot, cert_id))

    policy_name = ctx.unique_name("sim2real-cmd-policy-")
    region = ctx.region
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iot:Connect",
                "Resource": f"arn:aws:iot:{region}:{account_id}:client/{thing_name}",
            },
            {
                "Effect": "Allow",
                "Action": "iot:Subscribe",
                "Resource": (
                    f"arn:aws:iot:{region}:{account_id}:topicfilter/$aws/commands/things/"
                    f"{thing_name}/executions/+/request/json"
                ),
            },
            {
                "Effect": "Allow",
                "Action": "iot:Receive",
                "Resource": (
                    f"arn:aws:iot:{region}:{account_id}:topic/$aws/commands/things/"
                    f"{thing_name}/executions/*/request/json"
                ),
            },
            {
                "Effect": "Allow",
                "Action": "iot:Publish",
                "Resource": (
                    f"arn:aws:iot:{region}:{account_id}:topic/$aws/commands/things/"
                    f"{thing_name}/executions/*/response/json"
                ),
            },
        ],
    }
    iot.create_policy(policyName=policy_name, policyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iot.delete_policy(policyName=policy_name))
    iot.attach_policy(policyName=policy_name, target=cert_arn)
    ctx.on_cleanup(lambda: iot.detach_policy(policyName=policy_name, target=cert_arn))
    iot.attach_thing_principal(thingName=thing_name, principal=cert_arn)
    ctx.on_cleanup(lambda: iot.detach_thing_principal(thingName=thing_name, principal=cert_arn))

    command_id = ctx.unique_name("sim2real-cmd-")
    command = iot.create_command(
        commandId=command_id,
        namespace="AWS-IoT",
        payload={"content": b'{"action":"ping"}', "contentType": "application/json"},
    )
    command_arn = command["commandArn"]
    ctx.on_cleanup(lambda: iot.delete_command(commandId=command_id))

    with tempfile.TemporaryDirectory() as tmp:
        cert_path = Path(tmp, "cert.pem")
        key_path = Path(tmp, "key.pem")
        cert_path.write_text(cert["certificatePem"])
        key_path.write_text(cert["keyPair"]["PrivateKey"])

        incoming: "queue.Queue[tuple[str, bytes]]" = queue.Queue()
        connected = threading.Event()
        subscribed = threading.Event()

        client = _make_mqtt_client(mqtt, thing_name)

        def _on_connect(_client, _userdata, _flags, rc, *_args):
            if rc == 0 or str(rc) == "0" or getattr(rc, "value", None) == 0:
                connected.set()

        def _on_subscribe(_client, _userdata, _mid, *_args):
            subscribed.set()

        def _on_message(_client, _userdata, msg):
            incoming.put((msg.topic, msg.payload))

        client.on_connect = _on_connect
        client.on_subscribe = _on_subscribe
        client.on_message = _on_message

        context = ssl._create_unverified_context()
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        client.tls_set_context(context)

        client.connect(*ctx.endpoint_host(endpoint, 8883), keepalive=30)
        client.loop_start()
        try:
            if not connected.wait(timeout=15):
                raise AssertionError("device never established the MQTT connection to IoT Core")

            request_filter = f"$aws/commands/things/{thing_name}/executions/+/request/json"
            client.subscribe(request_filter, qos=1)
            if not subscribed.wait(timeout=15):
                raise AssertionError("device never received a SUBACK for the commands request topic")

            start_resp = jobs_data.start_command_execution(
                commandArn=command_arn, targetArn=thing_arn, executionTimeoutSeconds=60
            )
            execution_id = start_resp["executionId"]

            topic, _payload = _wait_for_message(incoming, timeout_s=30)
            topic_execution_id = topic.split("/executions/")[1].split("/")[0]
            assert topic_execution_id == execution_id, (
                "the execution id carried in the MQTT request topic does not match the "
                "id returned by StartCommandExecution"
            )

            response_topic = (
                f"$aws/commands/things/{thing_name}/executions/{execution_id}/response/json"
            )
            info = client.publish(response_topic, json.dumps({"status": "SUCCEEDED"}), qos=1)
            info.wait_for_publish(timeout=15)
            if not info.is_published():
                raise AssertionError("device's SUCCEEDED response was never acknowledged (PUBACK) by IoT Core")
        finally:
            client.loop_stop()
            client.disconnect()

    final = _poll_until_terminal(iot, execution_id, thing_arn, timeout_s=30)
    assert final["status"] == "SUCCEEDED", f"execution ended in unexpected status {final['status']!r}"

    listed = iot.list_command_executions(
        targetArn=thing_arn, startedTimeFilter={"after": "2020-01-01T00:00"}
    ).get("commandExecutions", [])
    assert any(e["executionId"] == execution_id for e in listed), (
        f"execution {execution_id} missing from ListCommandExecutions for {thing_arn}: {listed!r}"
    )

    iot.delete_command_execution(executionId=execution_id, targetArn=thing_arn)

    code, message = _error_code(lambda: iot.get_command_execution(executionId=execution_id, targetArn=thing_arn))
    assert code == "ResourceNotFoundException", (
        f"deleted execution {execution_id} still readable via GetCommandExecution (code={code!r})"
    )
    expected = f"Command execution {execution_id} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _make_mqtt_client(mqtt, client_id: str):
    try:
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
    except AttributeError:
        return mqtt.Client(client_id=client_id)


def _wait_for_message(incoming, timeout_s: float = 30.0):
    try:
        return incoming.get(timeout=timeout_s)
    except queue.Empty:
        raise AssertionError(
            "device never received a command execution request on the reserved MQTT topic"
        )


def _poll_until_terminal(iot, execution_id: str, target_arn: str, timeout_s: float = 30.0) -> dict:
    terminal = {"SUCCEEDED", "FAILED", "REJECTED", "TIMED_OUT"}
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = iot.get_command_execution(executionId=execution_id, targetArn=target_arn)
        if last["status"] in terminal:
            return last
        time.sleep(1.5)
    raise AssertionError(f"execution never reached a terminal status; last seen: {last}")


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a not-found error, but the call SUCCEEDED and returned {result!r}")


def _retire_certificate(iot, cert_id: str) -> None:
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
