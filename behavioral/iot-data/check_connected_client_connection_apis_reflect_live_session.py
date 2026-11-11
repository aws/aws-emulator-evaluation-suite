"""connected-client-connection-apis-reflect-live-session."""
from __future__ import annotations

import json
import os
import ssl
import tempfile
import threading
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "connected-client-connection-apis-reflect-live-session"
GROUP = "connection-management"
SERVICES = ["iot-data"]

# The broker is a public endpoint, so an unreachable MQTT connect fails the check.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _not_found(exc: ClientError) -> bool:
    """Teardown tolerates only an already-deleted resource; every other refusal raises."""
    return exc.response["Error"]["Code"] == "ResourceNotFoundException"


def _delete_certificate(iot, cert_id):
    """Teardown: detach policies, deactivate, then force-delete a certificate."""
    try:
        cert_arn = iot.describe_certificate(certificateId=cert_id)["certificateDescription"]["certificateArn"]
    except ClientError as exc:
        if not _not_found(exc):
            raise
        return
    for p in iot.list_attached_policies(target=cert_arn).get("policies", []):
        try:
            iot.detach_policy(policyName=p["policyName"], target=cert_arn)
        except ClientError as exc:
            if not _not_found(exc):
                raise
    try:
        iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    except ClientError as exc:
        if not _not_found(exc):
            raise
    try:
        iot.delete_certificate(certificateId=cert_id, forceDelete=True)
    except ClientError as exc:
        if not _not_found(exc):
            raise


def _delete_policy(iot, name):
    try:
        targets = iot.list_targets_for_policy(policyName=name).get("targets", [])
    except ClientError as exc:
        if not _not_found(exc):
            raise
        return
    for t in targets:
        try:
            iot.detach_policy(policyName=name, target=t)
        except ClientError as exc:
            if not _not_found(exc):
                raise
    try:
        iot.delete_policy(policyName=name)
    except ClientError as exc:
        if not _not_found(exc):
            raise


@tags(
    "axis:happy-path",
    "cap:c6",
    "concern:data-plane",
    "concern:representation",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """With a live MQTT client connected, GetConnection reports it connected with socket info,
    ListSubscriptions names its filter, SendDirectMessage reaches it, and disconnect is reflected.

    Reference: https://docs.aws.amazon.com/iot/latest/apireference/API_iotdata_GetConnection.html
    """
    import paho.mqtt.client as mqtt

    iot = ctx.client("iot")
    iot_data = ctx.client("iot-data")

    client_id = ctx.unique_name("sim2real-behav-iotdata-conn-")
    direct_topic = f"sim2real/behav/{ctx.unique_name('sim2real-behav-dm-')}/inbox"
    sub_topic_filter = f"sim2real/behav/{ctx.unique_name('sim2real-behav-sub-')}/+"
    sub_topic = sub_topic_filter.rsplit("/", 1)[0] + "/leaf"

    cert = iot.create_keys_and_certificate(setAsActive=True)
    cert_id = cert["certificateId"]
    cert_arn = cert["certificateArn"]
    # TagResource rejects certificate ARNs ("Invalid resource type in ARN: cert"), so the cert is
    # untagged and deleted by the cleanup below.
    ctx.on_cleanup(lambda: _delete_certificate(iot, cert_id))

    policy_name = ctx.unique_name("sim2real-behav-policy-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iot:*", "Resource": "*"}],
    }
    iot.create_policy(
        policyName=policy_name,
        policyDocument=json.dumps(policy_doc),
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_policy(iot, policy_name))
    iot.attach_policy(policyName=policy_name, target=cert_arn)

    endpoint_host = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]

    cert_file = tempfile.NamedTemporaryFile(prefix="sim2real-iotdata-cert-", suffix=".pem", delete=False, mode="w")
    key_file = tempfile.NamedTemporaryFile(prefix="sim2real-iotdata-key-", suffix=".pem", delete=False, mode="w")
    cert_file.write(cert["certificatePem"])
    cert_file.close()
    key_file.write(cert["keyPair"]["PrivateKey"])
    key_file.close()
    ctx.on_cleanup(lambda: os.unlink(cert_file.name))
    ctx.on_cleanup(lambda: os.unlink(key_file.name))

    state = {
        "connected": threading.Event(),
        "subscribed": threading.Event(),
        "received": [],
        "rc": None,
    }

    def _on_connect(_client, _userdata, _flags, rc, *_a):
        state["rc"] = int(rc)
        if int(rc) == 0:
            state["connected"].set()

    def _on_subscribe(_client, _userdata, _mid, *_a):
        state["subscribed"].set()

    def _on_message(_client, _userdata, msg):
        state["received"].append((msg.topic, bytes(msg.payload)))

    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=client_id)
    except (AttributeError, TypeError):
        client = mqtt.Client(client_id=client_id)
    client.tls_set(cert_reqs=ssl.CERT_NONE, certfile=cert_file.name, keyfile=key_file.name, tls_version=ssl.PROTOCOL_TLS_CLIENT)
    client.on_connect = _on_connect
    client.on_subscribe = _on_subscribe
    client.on_message = _on_message

    connect_deadline = time.time() + 60
    try:
        client.connect(*ctx.endpoint_host(endpoint_host, 8883), keepalive=30)
    except OSError as exc:
        raise AssertionError(f"MQTT connect to {endpoint_host!r}:8883 failed: {exc}") from exc
    client.loop_start()
    ctx.on_cleanup(client.loop_stop)
    while not state["connected"].wait(timeout=5):
        if time.time() >= connect_deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: MQTT never connected within 60s (last rc={state['rc']!r})"
            )

    try:
        client.subscribe(sub_topic_filter, qos=1)
        subacked = state["subscribed"].wait(timeout=15)
        assert subacked is True, f"{DATAPLANE_MARKER}: MQTT never SUBACKed, wait() returned {subacked!r}"

        # --- GetConnection: must reflect the socket that is actually open right now ---
        conn = iot_data.get_connection(clientId=client_id, includeSocketInformation=True)
        assert conn["connected"] is True, f"GetConnection reported connected={conn.get('connected')!r} while an MQTT session is open"
        assert conn["clientId"] == client_id, f"GetConnection returned clientId={conn.get('clientId')!r}, expected {client_id!r}"
        assert conn.get("sourceIp"), f"GetConnection with includeSocketInformation=True returned no sourceIp: {conn!r}"
        assert conn.get("sourcePort", 0) > 0, f"GetConnection with includeSocketInformation=True returned sourcePort={conn.get('sourcePort')!r}"

        # --- ListSubscriptions: must name the topic filter this exact client subscribed to ---
        subs = iot_data.list_subscriptions(clientId=client_id)
        filters = [s["topicFilter"] for s in subs.get("subscriptions", [])]
        assert sub_topic_filter in filters, (
            f"ListSubscriptions for {client_id!r} returned {filters!r}, expected it to include "
            f"the filter the client actually subscribed to, {sub_topic_filter!r}"
        )

        # --- SendDirectMessage: must deliver to the connected client over the open MQTT session ---
        payload = b"sim2real-behav-direct-message-payload"
        direct = iot_data.send_direct_message(clientId=client_id, topic=direct_topic, payload=payload)
        assert direct.get("traceId"), f"SendDirectMessage returned no traceId: {direct!r}"

        deadline = time.time() + 20
        while time.time() < deadline and not any(t == direct_topic for t, _p in state["received"]):
            time.sleep(0.3)
        matches = [p for t, p in state["received"] if t == direct_topic]
        assert matches, (
            f"{DATAPLANE_MARKER}: SendDirectMessage returned a traceId but the connected client "
            f"never received anything on {direct_topic!r}; messages seen: {state['received']!r}"
        )
        assert matches[0] == payload, (
            f"the delivered direct message was {matches[0]!r}, expected the exact bytes sent, {payload!r}"
        )
    finally:
        client.disconnect()
        client.loop_stop()

    # --- Effect-absent control: after disconnect, the live session this check proved is gone. ---
    deadline = time.time() + 30
    after = None
    while time.time() < deadline:
        after = iot_data.get_connection(clientId=client_id, includeSocketInformation=True)
        if after.get("connected") is False:
            break
        time.sleep(2)
    assert after is not None and after.get("connected") is False, (
        f"GetConnection must report connected=False after the client disconnected, got {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
