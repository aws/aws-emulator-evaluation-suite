"""e2e-command-execution-lifecycle-and-cleanup."""
from __future__ import annotations

import json
import os
import ssl
import queue
import tempfile
import threading
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-command-execution-lifecycle-and-cleanup"
GROUP = "e2e"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c6", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "dp:native", "plane:data")
def run(ctx) -> None:
    """A device completes a command execution over MQTT (the accepted topic answers),
    GetCommandExecution reports SUCCEEDED, and after DeleteCommandExecution Get fails
    with ResourceNotFoundException and its exact message."""
    import paho.mqtt.client as mqtt

    iot = ctx.client("iot")

    thing_name = ctx.unique_name("sim2real-iot-thing-")
    thing_arn = iot.create_thing(thingName=thing_name)["thingArn"]
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    keys = iot.create_keys_and_certificate(setAsActive=True)
    cert_arn = keys["certificateArn"]
    cert_id = keys["certificateId"]
    cert_pem = keys["certificatePem"]
    private_key = keys["keyPair"]["PrivateKey"]
    ctx.on_cleanup(lambda: _delete_cert(iot, cert_id))

    policy_name = ctx.unique_name("sim2real-iot-cmd-policy-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "iot:Connect", "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": ["iot:Publish", "iot:Receive"],
                "Resource": f"arn:aws:iot:{ctx.region}:*:topic/$aws/commands/things/{thing_name}/*",
            },
            {
                "Effect": "Allow",
                "Action": "iot:Subscribe",
                "Resource": f"arn:aws:iot:{ctx.region}:*:topicfilter/$aws/commands/things/{thing_name}/*",
            },
        ],
    }
    iot.create_policy(
        policyName=policy_name,
        policyDocument=json.dumps(policy_doc),
        tags=[{"Key": "sim2real", "Value": CHECK}],
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
        payload={"content": json.dumps({"action": "reboot"}).encode("utf-8"), "contentType": "application/json"},
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )["commandArn"]
    ctx.on_cleanup(lambda: iot.delete_command(commandId=command_id))

    # StartCommandExecution is served by the unified IoT data-plane endpoint
    # (iot:Data-ATS), reached through the "iot-jobs-data" client (the "iot-data"
    # client's operation set does not include command-execution operations).
    data_endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    jobs_data = ctx.client("iot-jobs-data", endpoint_url=ctx.endpoint_url(data_endpoint))
    start = jobs_data.start_command_execution(commandArn=command_arn, targetArn=thing_arn, executionTimeoutSeconds=300)
    execution_id = start["executionId"]
    ctx.on_cleanup(lambda: _delete_execution(iot, execution_id, thing_arn))

    data_ats_endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    cert_file = tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False)
    key_file = tempfile.NamedTemporaryFile(mode="w", suffix=".key", delete=False)
    try:
        cert_file.write(cert_pem)
        cert_file.close()
        key_file.write(private_key)
        key_file.close()

        ack_queue: "queue.Queue[str]" = queue.Queue()
        connected = threading.Event()
        subscribed = threading.Event()
        pending_subacks = {"count": 0}
        client = _make_mqtt_client(mqtt, thing_name)
        client.tls_set(
            cert_reqs=ssl.CERT_NONE,
            certfile=cert_file.name,
            keyfile=key_file.name,
        )

        accepted_topic = f"$aws/commands/things/{thing_name}/executions/{execution_id}/response/accepted/json"
        rejected_topic = f"$aws/commands/things/{thing_name}/executions/{execution_id}/response/rejected/json"
        response_topic = f"$aws/commands/things/{thing_name}/executions/{execution_id}/response/json"

        def on_connect(_client, _userdata, _flags, rc, *_args):
            if rc == 0 or str(rc) == "0" or getattr(rc, "value", None) == 0:
                connected.set()

        def on_message(_client, _userdata, msg):
            ack_queue.put(msg.topic)

        def on_subscribe(_client, _userdata, _mid, *_args):
            pending_subacks["count"] += 1
            if pending_subacks["count"] >= 2:
                subscribed.set()

        client.on_connect = on_connect
        client.on_message = on_message
        client.on_subscribe = on_subscribe
        client.connect(*ctx.endpoint_host(data_ats_endpoint, 8883), keepalive=30)
        client.loop_start()
        try:
            if not connected.wait(timeout=15.0):
                raise AssertionError("device never established the MQTT connection to IoT Core within 15s")
            client.subscribe(accepted_topic)
            client.subscribe(rejected_topic)
            if not subscribed.wait(timeout=15.0):
                raise AssertionError(
                    f"device never received SUBACKs for both response topics "
                    f"(got {pending_subacks['count']} of 2) within 15s"
                )
            client.publish(response_topic, json.dumps({"status": "SUCCEEDED"}), qos=1)

            arrived_topic = None
            try:
                arrived_topic = ack_queue.get(timeout=20.0)
            except queue.Empty:
                pass
        finally:
            client.loop_stop()
            client.disconnect()
    finally:
        os.unlink(cert_file.name)
        os.unlink(key_file.name)

    assert arrived_topic == accepted_topic, f"device's UpdateCommandExecution was not accepted (got {arrived_topic!r})"

    final_status = _poll_until(
        lambda: iot.get_command_execution(executionId=execution_id, targetArn=thing_arn)["status"],
        lambda status: status in ("SUCCEEDED", "FAILED", "REJECTED", "TIMED_OUT"),
        timeout_s=30.0,
    )
    assert final_status == "SUCCEEDED", f"execution ended in unexpected status {final_status!r}, expected SUCCEEDED"

    iot.delete_command_execution(executionId=execution_id, targetArn=thing_arn)
    code, message = _error_code(lambda: iot.get_command_execution(executionId=execution_id, targetArn=thing_arn))
    assert code == "ResourceNotFoundException", (
        f"GetCommandExecution after DeleteCommandExecution returned {code!r}, expected ResourceNotFoundException"
    )
    expected = f"Command execution {execution_id} cannot be found."
    assert message == expected, f"GetCommandExecution message {message!r} != {expected!r}"


def _make_mqtt_client(mqtt, client_id):
    try:
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=client_id)
    except AttributeError:
        return mqtt.Client(client_id=client_id)


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s; last seen: {last!r}")


def _error_code(fn):
    """Call fn(); return the (Code, Message) of the ClientError it raises; raise on success."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _delete_cert(iot, cert_id):
    try:
        iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_certificate(certificateId=cert_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_execution(iot, execution_id, target_arn):
    iot.delete_command_execution(executionId=execution_id, targetArn=target_arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
