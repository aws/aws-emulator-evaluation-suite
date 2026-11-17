"""mqtt-offline-persistent-session-discards-qos0-publishes-and-keeps-qos1."""
from __future__ import annotations

import json
import os
import shutil
import ssl
import socket
import tempfile
import threading
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "mqtt-offline-persistent-session-discards-qos0-publishes-and-keeps-qos1"
GROUP = "mqtt-data-plane"
SERVICES = ["iot"]


def _ats_endpoint(ctx) -> str:
    """The account's own iot:Data-ATS broker host, once its DNS record exists.

    The first DescribeEndpoint on a fresh account mints the hostname and it is
    unresolvable for up to a minute afterwards, which surfaces as socket.gaierror and reads like
    an unreachable broker. Wait for the record, then hand the host to the MQTT client.
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
    """A certificate must be detached from every policy/thing and INACTIVE before delete."""
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


def _provision_identity(ctx, iot, workdir: str, statements: list, scenario: str, label: str):
    """A device identity usable for mutual-TLS MQTT: thing + policy + certificate + PEM files.

    ``statements`` is the policy's Statement list verbatim, so a caller can scope by resource ARN
    rather than only by action. The PEM files go in a per-run mkdtemp directory, never a fixed
    /tmp path -- the harness host is shared and a predictable name is a cross-run clobber.
    """
    thing = ctx.unique_name("sim2real-iot-thing-")
    iot.create_thing(thingName=thing, attributePayload={"attributes": {"sim2real": scenario}})
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing))

    policy = ctx.unique_name("sim2real-iot-pol-")
    iot.create_policy(
        policyName=policy,
        policyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
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


def _mqtt_close(client) -> None:
    try:
        client.loop_stop()
        client.disconnect()
    except OSError:  # the broker may already have closed the socket
        pass


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


def _subscribe(client, state: dict, topic: str, qos: int = 1, timeout_s: int = 30) -> list:
    """Subscribe and return the SUBACK's granted QoS list. 128 means the broker refused."""
    _res, mid = client.subscribe(topic, qos=qos)
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        with state["lock"]:
            if mid in state["suback"]:
                return state["suback"][mid]
        time.sleep(0.1)
    raise AssertionError(f"no SUBACK for {topic!r} within {timeout_s}s")


def _publish_acked(client, topic: str, payload: bytes, timeout_s: int = 30) -> None:
    info = client.publish(topic, payload, qos=1)
    deadline = time.time() + timeout_s
    while time.time() < deadline and not info.is_published():
        time.sleep(0.1)
    assert info.is_published(), (
        f"the broker never PUBACKed the publish to {topic!r}; paho rc {info.rc!r}"
    )


def _payloads(state: dict, topic: str) -> list:
    with state["lock"]:
        return [m.payload for m in state["messages"] if m.topic == topic]


def _wait_for_payload(state: dict, topic: str, payload: bytes, timeout_s: int, what: str) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if payload in _payloads(state, topic):
            return
        time.sleep(0.2)
    raise AssertionError(f"{what} within {timeout_s}s; {topic!r} held {_payloads(state, topic)!r}")


def _connect_session(ctx, host: str, identity: dict, client_id: str, clean_session: bool,
                     register_cleanup: bool = True, timeout_s: int = 120):
    """An MQTT 3.1.1 session with an explicit cleanSession flag, capturing CONNACK sessionPresent.

    Separate from ``_mqtt_connect`` because the cleanSession bit and the sessionPresent flag the
    broker answers with are the subject here, and ``_mqtt_connect`` hardcodes cleanSession=True and
    discards the flags dict.
    """
    import paho.mqtt.client as mqtt

    state = {"rc": None, "session_present": None, "connected": threading.Event(),
             "suback": {}, "messages": [], "disconnects": [], "lock": threading.Lock()}

    def on_connect(_c, _u, flags, rc):
        state["rc"] = int(rc)
        # paho's VERSION1 callback spells the flag with a space, and reports it as 0/1.
        state["session_present"] = bool(flags.get("session present"))
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

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=client_id,
                         clean_session=clean_session)
    client.tls_set(cert_reqs=ssl.CERT_NONE, certfile=identity["cert_path"], keyfile=identity["key_path"],
                   tls_version=ssl.PROTOCOL_TLS_CLIENT)
    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_message = on_message
    client.on_disconnect = on_disconnect
    if register_cleanup:
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
        f"{client_id!r} (cleanSession={clean_session!r}) never got CONNACK rc=0 from {host}:8883 "
        f"within {timeout_s}s; last rc {state['rc']!r}, last exception {last!r}"
    )


def _discard_session(ctx, host: str, identity: dict, client_id: str) -> None:
    """Delete a persistent session by reconnecting once with cleanSession=1, then disconnecting.

    A persistent session is broker-side state keyed on the client id and survives every
    disconnect, so ``_mqtt_close`` does NOT undo it. Left behind it holds queued messages and
    subscriptions in this account for the session-expiry window.
    """
    try:
        client, _state = _connect_session(
            ctx, host, identity, client_id, clean_session=True, register_cleanup=False,
            timeout_s=60)
    except AssertionError:
        return
    _mqtt_close(client)


# ===== the check =====

@tags("axis:rejection", "cap:c6", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:native", "plane:data")
def run(ctx) -> None:
    """The broker's offline store is bounded by QoS, not by subscription: for the SAME offline
    persistent session and the SAME QoS-1 subscription, messages published at QoS 0 are discarded
    while messages published at QoS 1 are queued and delivered on resume."""
    iot = ctx.client("iot")
    host = _ats_endpoint(ctx)

    workdir = tempfile.mkdtemp(prefix="sim2real-iot-mqtt-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))

    scenario = "mqtt-offline-qos0-discarded"
    topic = f"sim2real/{ctx.unique_name('m')}/mixed"
    identity = _provision_identity(
        ctx, iot, workdir,
        [{"Effect": "Allow",
          "Action": ["iot:Connect", "iot:Publish", "iot:Subscribe", "iot:Receive"],
          "Resource": "*"}],
        scenario, "device",
    )

    # Registered BEFORE the session exists so LIFO runs it LAST: a persistent session survives
    # every disconnect and holds subscriptions and queued messages until it expires.
    persistent_id = ctx.unique_name("sim2real-iot-persist-")
    ctx.on_cleanup(lambda: _discard_session(ctx, host, identity, persistent_id))

    first, first_state = _connect_session(ctx, host, identity, persistent_id, clean_session=False)
    assert first_state["rc"] == 0, f"the persistent client's CONNACK was {first_state['rc']!r}"
    assert first_state["session_present"] is False, (
        f"the broker reported sessionPresent={first_state['session_present']!r} on the FIRST "
        f"connect of client id {persistent_id!r}, which has no prior session"
    )
    # The subscription is QoS 1, so it is capable of being queued. That is what makes the QoS-0
    # discard below a property of the PUBLISH, which is the single thing varied.
    granted = _subscribe(first, first_state, topic, qos=1)
    assert granted == [1], (
        f"the persistent subscriber's SUBACK on {topic!r} granted {granted!r}, expected [1]"
    )
    _mqtt_close(first)

    publisher, pub_state = _mqtt_connect(
        ctx, host, identity, ctx.unique_name("sim2real-iot-pub-"))
    assert pub_state["rc"] == 0, f"the publisher's CONNACK was {pub_state['rc']!r}, expected 0"

    # Vary exactly one thing: the publish QoS. QoS 0 goes on the wire FIRST, so it has strictly
    # more time to be stored than the QoS-1 messages whose arrival is its barrier.
    dropped = [json.dumps({"qos": 0, "seq": i, "run": ctx.unique_name("d-")}).encode()
               for i in range(3)]
    for payload in dropped:
        info = publisher.publish(topic, payload, qos=0)
        deadline = time.time() + 30
        while time.time() < deadline and not info.is_published():
            time.sleep(0.1)
        assert info.is_published(), (
            f"the QoS-0 publish to {topic!r} never left the client, so nothing was offered to the "
            f"broker's store; paho rc {info.rc!r}"
        )
    kept = [json.dumps({"qos": 1, "seq": i, "run": ctx.unique_name("k-")}).encode()
            for i in range(3)]
    for payload in kept:
        _publish_acked(publisher, topic, payload)

    resumed, resumed_state = _connect_session(
        ctx, host, identity, persistent_id, clean_session=False)
    assert resumed_state["rc"] == 0, f"the resumed CONNACK was {resumed_state['rc']!r}, expected 0"
    assert resumed_state["session_present"] is True, (
        f"the broker reported sessionPresent={resumed_state['session_present']!r} when resuming "
        f"{persistent_id!r} with cleanSession=0, so the session -- and its store -- was discarded"
    )

    # POSITIVE CONTROL / DIFFERENTIAL BARRIER: the QoS-1 messages must all arrive. Until they do,
    # an empty inbox is latency; once they have, it is the store's decision.
    deadline = time.time() + 120
    got: list = []
    while time.time() < deadline:
        got = _payloads(resumed_state, topic)
        if len([p for p in got if p in kept]) >= len(kept):
            break
        time.sleep(0.5)
    kept_seqs = sorted(json.loads(p)["seq"] for p in got if p in kept)
    assert kept_seqs == list(range(len(kept))), (
        f"the QoS-1 messages published while the session was offline were delivered as "
        f"{kept_seqs!r}, expected {list(range(len(kept)))!r}; the whole inbox was {got!r}"
    )
    # EFFECT ABSENT: not one QoS-0 message survived the offline window.
    survived = [p for p in got if p in dropped]
    assert survived == [], (
        f"messages published at QoS 0 to an OFFLINE persistent session were stored and delivered "
        f"on resume: {survived!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
