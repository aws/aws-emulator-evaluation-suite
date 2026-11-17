"""presence-lifecycle-events-separate-clean-disconnect-from-clientid-takeover."""
from __future__ import annotations

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

CHECK = "presence-lifecycle-events-separate-clean-disconnect-from-clientid-takeover"
GROUP = "mqtt-data-plane"
SERVICES = ["iot"]

_CLEAN_REASON = "CLIENT_INITIATED_DISCONNECT"


@tags(
    "axis:happy-path",
    "cap:c4",
    "cap:c6",
    "concern:data-plane",
    "concern:eventing",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """Presence lifecycle events distinguish a client's own DISCONNECT from a client-ID takeover.

    An observer sees connect, a client-initiated disconnect, connect, then a takeover disconnect
    that is not client-initiated and has a different reason; the displaced session drops.
    """
    iot = ctx.client("iot")
    host = _ats_endpoint(ctx)

    workdir = tempfile.mkdtemp(prefix="sim2real-iot-presence-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))

    identity = _provision_identity(
        ctx, iot, workdir,
        ["iot:Connect", "iot:Subscribe", "iot:Receive", "iot:Publish"],
        "presence-lifecycle-events", "device",
    )

    # No '#' or '+' anywhere in the subject client ID: such IDs receive no lifecycle events.
    subject_id = ctx.unique_name("sim2realpresence")
    t_connected = f"$aws/events/presence/connected/{subject_id}"
    t_disconnected = f"$aws/events/presence/disconnected/{subject_id}"

    observer, obs_state = _mqtt_connect(
        ctx, host, identity, ctx.unique_name("sim2real-iot-presence-obs-"))
    assert obs_state["rc"] == 0, (
        f"the observer's CONNACK was rc={obs_state['rc']!r}, expected 0"
    )
    for topic in (t_connected, t_disconnected):
        granted = _subscribe(observer, obs_state, topic, qos=1)
        assert granted == [1], (
            f"SUBACK for the reserved presence topic {topic!r} granted {granted!r}, expected [1]; "
            "128 means the broker refused the subscription and nothing below could be graded"
        )

    # ---- Leg 1: the subject connects. A connected event must name it.
    incumbent, inc_state = _mqtt_connect(ctx, host, identity, subject_id)
    assert inc_state["rc"] == 0, (
        f"the subject client {subject_id!r} could not connect (rc={inc_state['rc']!r}); every "
        "presence event below depends on this session existing"
    )
    connected = _wait_for_events(
        obs_state, t_connected, 1, 90,
        f"connecting {subject_id!r} published no event on {t_connected!r}",
    )
    assert connected[0]["clientId"] == subject_id, (
        f"the connected event named clientId {connected[0].get('clientId')!r}, expected "
        f"{subject_id!r}"
    )

    # ---- Leg 2: a CLEAN disconnect, initiated by the client itself.
    incumbent.disconnect()
    incumbent.loop_stop()
    clean = _wait_for_events(
        obs_state, t_disconnected, 1, 90,
        f"an MQTT DISCONNECT from {subject_id!r} published no event on {t_disconnected!r}",
    )[0]
    assert clean["clientId"] == subject_id, (
        f"the clean disconnect event named clientId {clean.get('clientId')!r}, expected "
        f"{subject_id!r}"
    )
    assert clean["clientInitiatedDisconnect"] is True, (
        "a client that sent an MQTT DISCONNECT produced clientInitiatedDisconnect="
        f"{clean.get('clientInitiatedDisconnect')!r}, expected True"
    )
    assert clean["disconnectReason"] == _CLEAN_REASON, (
        f"the clean disconnect reported disconnectReason {clean.get('disconnectReason')!r}, "
        f"expected {_CLEAN_REASON!r}"
    )

    # ---- Leg 3: reconnect the subject, then displace it with the SAME client ID.
    displaced, displaced_state = _mqtt_connect(ctx, host, identity, subject_id)
    assert displaced_state["rc"] == 0, (
        f"the subject client {subject_id!r} could not reconnect (rc={displaced_state['rc']!r})"
    )
    _wait_for_events(
        obs_state, t_connected, 2, 90,
        f"reconnecting {subject_id!r} published no second event on {t_connected!r}",
    )
    disconnects_before = len(displaced_state["disconnects"])

    newcomer, new_state = _mqtt_connect(ctx, host, identity, subject_id)
    assert new_state["rc"] == 0, (
        f"the second client using the already-connected ID {subject_id!r} was itself refused "
        f"(rc={new_state['rc']!r}); AWS IoT hands the ID to the NEWCOMER and drops the incumbent"
    )

    takeover = _wait_for_events(
        obs_state, t_disconnected, 2, 90,
        f"a second CONNECT on the in-use client ID {subject_id!r} published no second event on "
        f"{t_disconnected!r}; either no takeover happened or no lifecycle event was emitted",
    )[1]

    # INDEPENDENT SIDE-CHANNEL: the displaced client's own session must actually have been dropped,
    # not merely reported as dropped. This is what separates a real takeover from an emulator that
    # emits the event while leaving both sessions alive.
    _wait_until(
        lambda: len(displaced_state["disconnects"]) > disconnects_before, 90,
        f"the incumbent session for {subject_id!r} was never dropped by the broker (its own "
        f"on_disconnect never fired past {disconnects_before!r}), so the event above does not "
        "correspond to a real takeover",
    )

    assert takeover["clientId"] == subject_id, (
        f"the takeover disconnect event named clientId {takeover.get('clientId')!r}, expected "
        f"{subject_id!r}"
    )
    assert takeover["clientInitiatedDisconnect"] is False, (
        "a client displaced by another using the same client ID reported "
        f"clientInitiatedDisconnect={takeover.get('clientInitiatedDisconnect')!r}, expected False: "
        "the broker, not the client, ended that session"
    )
    assert takeover["disconnectReason"] != _CLEAN_REASON, (
        f"the takeover disconnect reported the same disconnectReason as the clean one "
        f"({takeover.get('disconnectReason')!r}); a broker-initiated eviction and a client's own "
        f"DISCONNECT are different events and must not share {_CLEAN_REASON!r}"
    )
    assert takeover["disconnectReason"], (
        f"the takeover disconnect carried an empty disconnectReason "
        f"({takeover.get('disconnectReason')!r})"
    )

    # The newcomer holds the ID: proven by a round trip on its own session, not by its CONNACK.
    topic = f"sim2real/{ctx.unique_name('pt')}/after-takeover"
    granted = _subscribe(newcomer, new_state, topic, qos=1)
    assert granted == [1], (
        f"the newcomer's SUBACK for {topic!r} granted {granted!r}, expected [1]"
    )
    payload = json.dumps({"marker": ctx.unique_name("after-")}).encode()
    info = newcomer.publish(topic, payload, qos=1)
    deadline = time.time() + 30
    while time.time() < deadline and not info.is_published():
        time.sleep(0.1)
    assert info.is_published(), (
        f"the broker never PUBACKed the newcomer's publish to {topic!r}, so the newcomer did not "
        "really win the client ID"
    )
    _wait_for_inbox(
        new_state, lambda m: m.payload == payload, 1, 60,
        f"the newcomer's own publish on {topic!r} never came back, so its session is not usable "
        "after the takeover",
    )
    _mqtt_close(displaced)


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


def _mqtt_connect(ctx, host: str, identity: dict, client_id: str, timeout_s: int = 120):
    """A mutually authenticated MQTT 3.1.1 session, with a bounded CONNACK retry and NO reconnect.

    reconnect_delay_set pushes paho's first background reconnect far past every deadline in this
    file, so a client the broker deliberately evicted stays evicted instead of stealing its client ID
    back and turning the takeover leg into a flap.
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
    client.reconnect_delay_set(min_delay=10_000, max_delay=10_000)
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
        except (OSError, ssl.SSLError) as exc:
            last = exc
            client.loop_stop()
        state["connected"].clear()
        time.sleep(3)
    raise AssertionError(
        f"{client_id!r} never got CONNACK rc=0 from {host}:8883 within {timeout_s}s; "
        f"last rc {state['rc']!r}, last exception {last!r}"
    )


def _mqtt_close(client) -> None:
    """Teardown only: the session is going away either way."""
    try:
        client.loop_stop()
        client.disconnect()
    except OSError:
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


def _wait_for_events(state: dict, topic: str, count: int, timeout_s: int, what: str) -> list[dict]:
    """The decoded JSON bodies of the first *count* messages on *topic*, in arrival order."""
    hits = _wait_for_inbox(state, lambda m: m.topic == topic, count, timeout_s, what)
    return [json.loads(m.payload) for m in hits[:count]]


def _wait_until(predicate, timeout_s: int, what: str) -> None:
    """Bounded retry on a local observation; RAISES on timeout."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.2)
    raise AssertionError(f"{what} (waited {timeout_s}s)")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
