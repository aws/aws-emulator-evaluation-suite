"""iot-retained-message-is-pushed-on-subscribe-with-the-retain-flag-set."""
from __future__ import annotations

import json
import os
import shutil
import socket
import ssl
import tempfile
import threading
import time

from botocore.config import Config

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "iot-retained-message-is-pushed-on-subscribe-with-the-retain-flag-set"
GROUP = 'mqtt-data-plane'
SERVICES = ['iot']


def _ats_endpoint(ctx) -> str:
    """The account's own iot:Data-ATS broker host, once its DNS record exists.

    On a fresh account the first DescribeEndpoint mints the hostname and
    it is unresolvable for up to a minute afterwards, so paho raises socket.gaierror and the
    check reads as an unreachable broker. Wait for the record, then hand the host to the client.
    """
    host = ctx.client("iot").describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    deadline = time.time() + 180
    last = None
    while time.time() < deadline:
        try:
            socket.getaddrinfo(*ctx.endpoint_host(host, 8883))
            return host
        except OSError as exc:
            last = exc
            time.sleep(3)
    raise AssertionError(f"the ATS endpoint {host!r} never resolved in DNS: {last!r}")


def _error_code(fn):
    """The AWS (code, message) raised by ``fn``, or a loud sentinel code if it wrongly SUCCEEDS."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - the code is the subject of the assertion
        resp = getattr(exc, "response", None) or {}
        err = resp.get("Error") or {}
        code = err.get("Code")
        return (code, err.get("Message")) if code else (f"NON-AWS-EXCEPTION:{type(exc).__name__}", None)
    return "UNEXPECTED-SUCCESS", None


def _delete_policy(iot, name: str) -> None:
    """A policy cannot be deleted while attached to a target or while extra versions exist."""
    for v in iot.list_policy_versions(policyName=name).get("policyVersions", []):
        if not v.get("isDefaultVersion"):
            try:
                iot.delete_policy_version(policyName=name, policyVersionId=v["versionId"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
    for target in iot.list_targets_for_policy(policyName=name).get("targets", []):
        iot.detach_policy(policyName=name, target=target)
    iot.delete_policy(policyName=name)


def _delete_certificate(iot, cert_id: str) -> None:
    """A certificate must be detached from every policy/thing and set INACTIVE before delete."""
    try:
        arn = iot.describe_certificate(certificateId=cert_id)[
            "certificateDescription"]["certificateArn"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    for p in iot.list_attached_policies(target=arn).get("policies", []):
        iot.detach_policy(policyName=p["policyName"], target=arn)
    for t in iot.list_principal_things(principal=arn).get("things", []):
        try:
            iot.detach_thing_principal(thingName=t, principal=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    iot.delete_certificate(certificateId=cert_id, forceDelete=True)


def _provision_identity(ctx, iot, workdir: str, actions: list[str], scenario: str, label: str):
    """A device identity usable for mutual-TLS MQTT: thing + policy + certificate + PEM files.

    The PEM files go in a per-run mkdtemp directory, never a fixed /tmp path -- the harness host
    is shared, and a predictable name is a measured cross-run clobber.
    """
    thing = ctx.unique_name("sim2real-iot-thing-")
    iot.create_thing(thingName=thing, attributePayload={"attributes": {"sim2real": scenario}})
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing))

    policy = ctx.unique_name("sim2real-iot-pol-")
    iot.create_policy(
        policyName=policy,
        policyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}],
        }),
        tags=[{"Key": "sim2real", "Value": scenario}],
    )
    ctx.on_cleanup(lambda: _delete_policy(iot, policy))

    cert = iot.create_keys_and_certificate(setAsActive=True)
    cert_id, cert_arn = cert["certificateId"], cert["certificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate(iot, cert_id))
    iot.attach_policy(policyName=policy, target=cert_arn)
    ctx.on_cleanup(lambda: iot.detach_policy(policyName=policy, target=cert_arn))
    iot.attach_thing_principal(thingName=thing, principal=cert_arn)
    ctx.on_cleanup(lambda: iot.detach_thing_principal(thingName=thing, principal=cert_arn))

    cert_path = os.path.join(workdir, f"{label}-cert.pem")
    key_path = os.path.join(workdir, f"{label}-key.pem")
    with open(cert_path, "w") as fh:
        fh.write(cert["certificatePem"])
    with open(key_path, "w") as fh:
        fh.write(cert["keyPair"]["PrivateKey"])
    return {"thing": thing, "policy": policy, "cert_id": cert_id, "cert_arn": cert_arn,
            "cert_path": cert_path, "key_path": key_path}


def _mqtt_connect(ctx, host: str, identity: dict, client_id: str, timeout_s: int = 120):
    """A mutually-authenticated MQTT 3.1.1 session, with a bounded CONNACK retry.

    The retry is on rc != 0 rather than a bare sleep because the certificate's policy attachment
    is eventually consistent at the broker; a successful CONNACK is therefore also the barrier
    proving the policy is in force.
    """
    import paho.mqtt.client as mqtt

    state = {"rc": None, "connected": threading.Event(), "suback": {}, "messages": [],
             "disconnects": [], "lock": threading.Lock()}

    def on_connect(_c, _u, _flags, rc):
        state["rc"] = int(rc)
        if int(rc) == 0:
            state["connected"].set()

    def on_subscribe(_c, _u, mid, granted_qos):
        with state["lock"]:
            state["suback"][mid] = [int(q) for q in granted_qos]

    def on_message(_c, _u, msg):
        with state["lock"]:
            state["messages"].append(msg)

    def on_disconnect(_c, _u, rc):
        state["disconnects"].append(int(rc))

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=client_id, clean_session=True)
    client.tls_set(cert_reqs=ssl.CERT_NONE, certfile=identity["cert_path"], keyfile=identity["key_path"],
                   tls_version=ssl.PROTOCOL_TLS_CLIENT)
    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_message = on_message
    client.on_disconnect = on_disconnect
    ctx.on_cleanup(lambda: _mqtt_close(client))

    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        try:
            client.connect(*ctx.endpoint_host(host, 8883), keepalive=30)
            client.loop_start()
            if state["connected"].wait(timeout=20):
                return client, state
            client.loop_stop()
        except Exception as exc:  # noqa: BLE001 - retried below, reported if it never clears
            last = exc
            try:
                client.loop_stop()
            except Exception:  # noqa: BLE001
                pass
        state["connected"].clear()
        time.sleep(3)
    raise AssertionError(
        f"{client_id!r} never got CONNACK rc=0 from {host}:8883 within {timeout_s}s; "
        f"last rc {state['rc']!r}, last exception {last!r}"
    )


def _mqtt_close(client) -> None:
    try:
        client.loop_stop()
        client.disconnect()
    except OSError:  # the broker may already have closed the socket
        pass


def _subscribe(client, state: dict, topic: str, qos: int = 1, timeout_s: int = 30) -> list[int]:
    """Subscribe and return the SUBACK's granted QoS list. 128 means the broker refused."""
    _res, mid = client.subscribe(topic, qos=qos)
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        with state["lock"]:
            if mid in state["suback"]:
                return state["suback"][mid]
        time.sleep(0.1)
    raise AssertionError(f"no SUBACK for {topic!r} within {timeout_s}s")


def _publish_acked(client, topic: str, payload: bytes, retain: bool, timeout_s: int = 30) -> None:
    info = client.publish(topic, payload, qos=1, retain=retain)
    deadline = time.time() + timeout_s
    while time.time() < deadline and not info.is_published():
        time.sleep(0.1)
    assert info.is_published(), (
        f"the broker never PUBACKed the publish to {topic!r} (retain={retain!r}); rc {info.rc!r}"
    )


def _inbox(state: dict, topic: str) -> list:
    with state["lock"]:
        return [m for m in state["messages"] if m.topic == topic]


def _wait_for_topic(state: dict, topic: str, timeout_s: int, what: str):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        hits = _inbox(state, topic)
        if hits:
            return hits[0]
        time.sleep(0.2)
    with state["lock"]:
        seen = [(m.topic, m.payload) for m in state["messages"]]
    raise AssertionError(f"{what} within {timeout_s}s; the inbox held {seen!r}")


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:eventing",
    "dp:native",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A retained message is replayed with the retain bit set to a client that subscribes after the
    retained publish, a live publish arrives with the bit clear, and once the retained message is
    deleted a fresh subscriber gets nothing."""
    iot = ctx.client("iot")
    host = _ats_endpoint(ctx)
    # The HTTP data-plane client gets a wider retry budget than botocore's default three
    # attempts: a freshly minted ATS DNS record resolves intermittently for a while, and an
    # EndpointConnectionError there reads exactly like a broken data plane.
    iot_data = ctx.client(
        "iot-data",
        endpoint_url=ctx.endpoint_url(host),
        config=Config(retries={"max_attempts": 10, "mode": "standard"}),
    )

    workdir = tempfile.mkdtemp(prefix="sim2real-iot-mqtt-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))

    # iot:RetainPublish is a separate action from iot:Publish: without it the broker silently
    # refuses the retained publish and there is no retained state to replay.
    identity = _provision_identity(
        ctx, iot, workdir,
        ["iot:Connect", "iot:Publish", "iot:RetainPublish", "iot:Subscribe", "iot:Receive"],
        "mqtt-retained-replay", "device",
    )

    base = ctx.unique_name("m")
    topic = f"sim2real/{base}/retain"
    sibling = f"sim2real/{base}/sibling"

    publisher, pub_state = _mqtt_connect(
        ctx, host, identity, ctx.unique_name("sim2real-iot-pub-"))
    assert pub_state["rc"] == 0, f"the publisher's CONNACK was {pub_state['rc']!r}"

    retained_payload = json.dumps({"marker": ctx.unique_name("retained-")}).encode()
    _publish_acked(publisher, topic, retained_payload, retain=True)
    # Registered immediately: a retained message outlives every session and would otherwise
    # poison a later run's GetRetainedMessage on this topic. The HTTP path is used because it
    # does not depend on an MQTT session that may already be torn down.
    ctx.on_cleanup(lambda: iot_data.publish(topic=topic, payload=b"", qos=1, retain=True))

    # A client that was NOT connected when the retained publish happened.
    late, late_state = _mqtt_connect(ctx, host, identity, ctx.unique_name("sim2real-iot-late-"))
    late_granted = _subscribe(late, late_state, topic, qos=1)
    assert late_granted == [1], f"the late subscriber's SUBACK granted {late_granted!r}"
    first_msg = _wait_for_topic(
        late_state, topic, 60,
        f"the broker never replayed the retained message on {topic!r} to a new subscriber",
    )
    assert first_msg.payload == retained_payload, (
        f"the replay carried {first_msg.payload!r}, published {retained_payload!r}"
    )
    assert first_msg.retain is True, (
        f"the replayed message did not carry the retain bit: {first_msg.retain!r}"
    )

    live_payload = json.dumps({"marker": ctx.unique_name("live-")}).encode()
    _publish_acked(publisher, topic, live_payload, retain=False)
    deadline = time.time() + 60
    live_msg = None
    while time.time() < deadline and live_msg is None:
        for m in _inbox(late_state, topic):
            if m.payload == live_payload:
                live_msg = m
                break
        time.sleep(0.2)
    assert live_msg is not None, (
        f"a live publish on {topic!r} never reached the already-subscribed client; it held "
        f"{[m.payload for m in _inbox(late_state, topic)]!r}"
    )
    assert live_msg.retain is False, (
        f"a live publish to an already-subscribed client carried the retain bit: {live_msg.retain!r}"
    )

    # Delete the retained message with a zero-length retained publish.
    _publish_acked(publisher, topic, b"", retain=True)
    deadline = time.time() + 60
    code, message = _error_code(lambda: iot_data.get_retained_message(topic=topic))
    while code != "ResourceNotFoundException" and time.time() < deadline:
        time.sleep(2)
        code, message = _error_code(lambda: iot_data.get_retained_message(topic=topic))
    assert code == "ResourceNotFoundException", (
        f"after a zero-length retained publish, GetRetainedMessage({topic!r}) returned {code!r}"
    )
    expected = "Retained message not found"
    assert message == expected, f"GetRetainedMessage message {message!r} != {expected!r}"

    # A THIRD fresh subscriber must be replayed nothing. The barrier is a control publish on a
    # sibling topic in the same subscription batch: when that arrives, the broker has finished
    # serving this client's subscriptions, so an empty retain inbox is a deletion, not latency.
    fresh, fresh_state = _mqtt_connect(ctx, host, identity, ctx.unique_name("sim2real-iot-fresh-"))
    fresh_retain_granted = _subscribe(fresh, fresh_state, topic, qos=1)
    fresh_sibling_granted = _subscribe(fresh, fresh_state, sibling, qos=1)
    assert fresh_retain_granted == [1], f"{fresh_retain_granted!r}"
    assert fresh_sibling_granted == [1], f"{fresh_sibling_granted!r}"
    control_payload = json.dumps({"marker": ctx.unique_name("control-")}).encode()
    _publish_acked(publisher, sibling, control_payload, retain=False)
    control_msg = _wait_for_topic(
        fresh_state, sibling, 60, "the settle barrier itself did not deliver")
    assert control_msg.payload == control_payload, f"{control_msg.payload!r}"

    third_inbox = _inbox(fresh_state, topic)
    assert third_inbox == [], (
        f"a deleted retained message was still replayed to a fresh subscriber: "
        f"{[(m.payload, m.retain) for m in third_inbox]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
