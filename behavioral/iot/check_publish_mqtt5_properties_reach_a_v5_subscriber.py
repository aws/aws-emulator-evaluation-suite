"""publish-mqtt5-properties-reach-a-v5-subscriber."""
from __future__ import annotations

import base64
import json
import os
import shutil
import socket
import ssl
import tempfile
import threading
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "publish-mqtt5-properties-reach-a-v5-subscriber"
GROUP = "mqtt-data-plane"
SERVICES = ["iot"]

_MESSAGE_EXPIRY_S = 300
_USER_PROPERTIES = [{"sim2real-a": "alpha"}, {"sim2real-b": "beta"}]


@tags(
    "axis:happy-path",
    "cap:c6",
    "concern:data-plane",
    "concern:eventing",
    "concern:representation",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """The iot-data Publish API's MQTT5 property parameters really reach an MQTT 5 subscriber.

    A control publish with no properties arrives with none, and a publish setting every modelled
    MQTT5 property arrives over MQTT 5 carrying each one.
    """
    iot = ctx.client("iot")
    data = ctx.client("iot-data")
    host = _ats_endpoint(ctx)

    workdir = tempfile.mkdtemp(prefix="sim2real-iot-mqtt5-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))

    identity = _provision_identity(
        ctx, iot, workdir,
        ["iot:Connect", "iot:Subscribe", "iot:Receive", "iot:Publish"],
        "mqtt5-publish-properties", "device",
    )

    base = ctx.unique_name("sim2real5")
    topic = f"{base}/telemetry"
    response_topic = f"{base}/reply"

    client, state = _mqtt5_connect(ctx, host, identity, ctx.unique_name("sim2real-iot-v5sub-"))
    assert state["reason"] == 0, (
        f"the MQTT 5 subscriber's CONNACK reason code was {state['reason']!r}, expected 0"
    )
    granted = _subscribe(client, state, topic, qos=1)
    assert granted == [1], (
        f"SUBACK for {topic!r} granted {granted!r}, expected [1]; a value >= 128 means the broker "
        "refused the subscription and nothing below could be graded"
    )

    # ---- CONTROL: an identical publish with no properties must deliver NONE of them.
    control_payload = json.dumps({"marker": ctx.unique_name("control-")}).encode()
    data.publish(topic=topic, qos=1, payload=control_payload)
    control = _wait_for_inbox(
        state, lambda m: m.payload == control_payload, 1, 60,
        f"the control publish never reached the MQTT 5 subscriber on {topic!r}; the wiring is "
        "broken before any property is examined",
    )[0]
    for name in ("ContentType", "ResponseTopic", "CorrelationData", "UserProperty",
                 "PayloadFormatIndicator"):
        # The None default is the correct polarity here: it feeds an assertion that the property is
        # ABSENT, so the default cannot supply the value the assertion exists to detect.
        assert _prop(control, name) is None, (
            f"a publish that set no MQTT5 properties still delivered {name}="
            f"{_prop(control, name)!r}; the control leg must show these absent, otherwise the "
            "property assertions below could be satisfied by a constant"
        )

    # ---- SUBJECT: every modelled MQTT5 property set on one publish.
    payload = json.dumps({"marker": ctx.unique_name("props-"), "temp": 42}).encode()
    correlation_raw = ctx.unique_name("corr-").encode()
    correlation_b64 = base64.b64encode(correlation_raw).decode()

    data.publish(
        topic=topic,
        qos=1,
        payload=payload,
        contentType="application/json",
        responseTopic=response_topic,
        correlationData=correlation_b64,
        payloadFormatIndicator="UTF8_DATA",
        userProperties=_USER_PROPERTIES,
        messageExpiry=_MESSAGE_EXPIRY_S,
    )
    msg = _wait_for_inbox(
        state, lambda m: m.payload == payload, 1, 60,
        f"the property-carrying publish never reached the MQTT 5 subscriber on {topic!r}",
    )[0]

    assert msg.payload == payload, (
        f"the broker delivered payload {msg.payload!r}, published {payload!r}"
    )
    assert msg.topic == topic, (
        f"the message was delivered on topic {msg.topic!r}, published to {topic!r}"
    )

    assert _prop(msg, "ContentType") == "application/json", (
        f"the delivered MQTT5 ContentType was {_prop(msg, 'ContentType')!r}, published "
        "'application/json'"
    )
    assert _prop(msg, "ResponseTopic") == response_topic, (
        f"the delivered MQTT5 ResponseTopic was {_prop(msg, 'ResponseTopic')!r}, published "
        f"{response_topic!r}"
    )
    assert _prop(msg, "PayloadFormatIndicator") == 1, (
        f"the delivered MQTT5 PayloadFormatIndicator was "
        f"{_prop(msg, 'PayloadFormatIndicator')!r}, expected 1 for payloadFormatIndicator="
        "'UTF8_DATA' (MQTT 5.0 3.3.2.3.2 maps UTF-8 payloads to 1 and raw bytes to 0)"
    )

    expected_user_props = [(k, v) for entry in _USER_PROPERTIES for k, v in entry.items()]
    got_user_props = [(str(k), str(v)) for k, v in (_prop(msg, "UserProperty") or [])]
    assert got_user_props == expected_user_props, (
        f"the delivered MQTT5 User Properties were {got_user_props!r}, published "
        f"{expected_user_props!r} — an implementation that accepts the "
        "x-amz-mqtt5-user-properties header and drops it delivers an empty list"
    )

    expiry = _prop(msg, "MessageExpiryInterval")
    assert expiry is not None and 0 < expiry <= _MESSAGE_EXPIRY_S, (
        f"the delivered MQTT5 MessageExpiryInterval was {expiry!r}, expected a value in "
        f"(0, {_MESSAGE_EXPIRY_S}]: the broker must forward the interval, decremented by however "
        "long the message waited, never absent and never larger than what was published"
    )

    # Deliberately last: CorrelationData is base64 on the API and raw bytes on the wire.
    assert _prop(msg, "CorrelationData") == correlation_raw, (
        f"the delivered MQTT5 CorrelationData was {_prop(msg, 'CorrelationData')!r}, expected the "
        f"base64-DECODED bytes {correlation_raw!r} of the published {correlation_b64!r}"
    )


def _prop(message, name: str):
    """One MQTT5 property off a paho message, or None when the property is not present.

    paho only sets attributes for properties actually on the wire, so a missing property raises
    AttributeError; collapsing that to None lets both the presence and the absence assertions above
    read the same way and carry a value in their failure message.
    """
    props = getattr(message, "properties", None)
    if props is None:
        return None
    return getattr(props, name, None)


def _ats_endpoint(ctx) -> str:
    """The account's own iot:Data-ATS broker host, once its DNS record exists.

    In an account that never asked before, the first DescribeEndpoint MINTS the hostname; it stays
    unresolvable for up to a minute, which surfaces as socket.gaierror and reads as an unreachable
    broker. Wait for the record with a deadline, then hand the host to the client.
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


def _delete_policy(iot, name: str) -> None:
    """Teardown only: a policy cannot be deleted while attached or while extra versions exist."""
    from botocore.exceptions import ClientError
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
    """Teardown only: a certificate must be fully detached and INACTIVE before it can be deleted."""
    from botocore.exceptions import ClientError
    try:
        arn = iot.describe_certificate(
            certificateId=cert_id)["certificateDescription"]["certificateArn"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
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
    """A device identity usable for mutual-TLS MQTT: policy + certificate + PEM files on disk."""
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

    cert_path = os.path.join(workdir, f"{label}-cert.pem")
    key_path = os.path.join(workdir, f"{label}-key.pem")
    with open(cert_path, "w") as fh:
        fh.write(cert["certificatePem"])
    with open(key_path, "w") as fh:
        fh.write(cert["keyPair"]["PrivateKey"])
    return {"policy": policy, "cert_id": cert_id, "cert_arn": cert_arn,
            "cert_path": cert_path, "key_path": key_path}


def _mqtt5_connect(ctx, host: str, identity: dict, client_id: str, timeout_s: int = 120):
    """A mutually authenticated MQTT **5** session, with a bounded CONNACK retry.

    MQTT 5 is required because MQTT 3.1.1 has no property fields at all: a 3.1.1 subscriber cannot
    observe the six parameters this check exists to grade. The retry is on a non-zero reason code
    rather than a bare sleep because the certificate's policy attachment is eventually consistent at
    the broker; a successful CONNACK is therefore also the barrier proving the policy is in force.
    """
    import paho.mqtt.client as mqtt

    state = {"reason": None, "connected": threading.Event(), "suback": {}, "messages": [],
             "disconnects": [], "lock": threading.Lock()}

    def on_connect(_c, _u, _flags, reason_code, _properties=None):
        state["reason"] = int(getattr(reason_code, "value", reason_code))
        if state["reason"] == 0:
            state["connected"].set()

    def on_subscribe(_c, _u, mid, reason_codes, _properties=None):
        with state["lock"]:
            state["suback"][mid] = [int(getattr(rc, "value", rc)) for rc in reason_codes]

    def on_message(_c, _u, msg):
        with state["lock"]:
            state["messages"].append(msg)

    def on_disconnect(_c, _u, _flags, reason_code, _properties=None):
        state["disconnects"].append(int(getattr(reason_code, "value", reason_code)))

    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=client_id,
        protocol=mqtt.MQTTv5,
    )
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
            client.connect(*ctx.endpoint_host(host, 8883), keepalive=30, clean_start=True)
            client.loop_start()
            if state["connected"].wait(timeout=20):
                return client, state
            client.loop_stop()
        except (OSError, ssl.SSLError) as exc:
            last = exc
            client.loop_stop()
        state["connected"].clear()
        time.sleep(3)
    raise AssertionError(
        f"{client_id!r} never got an MQTT 5 CONNACK with reason 0 from {host}:8883 within "
        f"{timeout_s}s; last reason {state['reason']!r}, last exception {last!r}"
    )


def _mqtt_close(client) -> None:
    """Teardown only: the session is going away either way."""
    try:
        client.loop_stop()
        client.disconnect()
    except OSError:
        pass


def _subscribe(client, state: dict, topic: str, qos: int = 1, timeout_s: int = 30) -> list[int]:
    """Subscribe and return the SUBACK reason codes. A value >= 128 means the broker refused."""
    _res, mid = client.subscribe(topic, qos=qos)
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        with state["lock"]:
            if mid in state["suback"]:
                return state["suback"][mid]
        time.sleep(0.1)
    raise AssertionError(f"no SUBACK for {topic!r} within {timeout_s}s")


def _inbox(state: dict, predicate) -> list:
    with state["lock"]:
        return [m for m in state["messages"] if predicate(m)]


def _wait_for_inbox(state: dict, predicate, count: int, timeout_s: int, what: str) -> list:
    """Bounded retry for broker pushes; RAISES on timeout rather than returning what it has."""
    deadline = time.time() + timeout_s
    hits: list = []
    while time.time() < deadline:
        hits = _inbox(state, predicate)
        if len(hits) >= count:
            return hits
        time.sleep(0.2)
    with state["lock"]:
        seen = [(m.topic, m.payload) for m in state["messages"]]
    raise AssertionError(
        f"{what}: only {len(hits)!r} of {count!r} arrived within {timeout_s}s; inbox held {seen!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
