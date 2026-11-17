"""iot-mqtt-publish-is-delivered-to-a-matching-subscriber-and-not-to-a-non-matching-one."""
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

CHECK = "iot-mqtt-publish-is-delivered-to-a-matching-subscriber-and-not-to-a-non-matching-one"
GROUP = 'mqtt-data-plane'
SERVICES = ['iot']

_BARRIER_PUBLISHES = 10


def _ats_endpoint(ctx) -> str:
    """The account's own iot:Data-ATS broker host, once its DNS record exists.

    In a fresh account the first DescribeEndpoint MINTS the hostname and
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
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        arn = None
    if arn:
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
    """A device identity usable for mutual-TLS MQTT: policy + certificate + PEM files on disk.

    The PEM files go in a per-run mkdtemp directory, never a fixed /tmp path -- the harness host
    is shared, and a predictable name is a measured cross-run clobber.
    """
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

    cert_path = os.path.join(workdir, f"{label}-cert.pem")
    key_path = os.path.join(workdir, f"{label}-key.pem")
    with open(cert_path, "w") as fh:
        fh.write(cert["certificatePem"])
    with open(key_path, "w") as fh:
        fh.write(cert["keyPair"]["PrivateKey"])
    return {"policy": policy, "cert_id": cert_id, "cert_arn": cert_arn,
            "cert_path": cert_path, "key_path": key_path}


def _mqtt_connect(ctx, host: str, identity: dict, client_id: str, timeout_s: int = 120):
    """A mutually-authenticated MQTT 3.1.1 session, with a bounded CONNACK retry.

    The retry is on rc != 0 rather than a bare sleep because the certificate's policy
    attachment is eventually consistent at the broker; a successful CONNACK is therefore also
    the barrier proving the policy is in force.
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
    """paho reports a session that is already gone as a return code, not an exception."""
    client.loop_stop()
    client.disconnect()


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


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:eventing",
    "dp:native",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """The MQTT broker really routes: a certificate-authenticated publish reaches a subscriber
    whose topic filter matches, byte-identically and with the frame flags intact, and never
    reaches one whose filter does not."""
    iot = ctx.client("iot")
    host = _ats_endpoint(ctx)

    workdir = tempfile.mkdtemp(prefix="sim2real-iot-mqtt-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))

    identity = _provision_identity(
        ctx, iot, workdir,
        ["iot:Connect", "iot:Publish", "iot:Subscribe", "iot:Receive"],
        "mqtt-topic-filter-routing", "device",
    )

    base = ctx.unique_name("m")
    other = ctx.unique_name("m")
    topic = f"sim2real/{base}/telemetry"
    matching_filter = f"sim2real/{base}/+"
    other_filter = f"sim2real/{other}/#"
    other_control = f"sim2real/{other}/control"

    matcher, m_state = _mqtt_connect(ctx, host, identity, ctx.unique_name("sim2real-iot-match-"))
    nonmatcher, o_state = _mqtt_connect(ctx, host, identity, ctx.unique_name("sim2real-iot-other-"))
    connect_rcs = [m_state["rc"], o_state["rc"]]
    assert connect_rcs == [0, 0], f"CONNACK codes were {connect_rcs!r}, expected [0, 0]"

    m_granted = _subscribe(matcher, m_state, matching_filter, qos=1)
    o_granted = _subscribe(nonmatcher, o_state, other_filter, qos=1)
    assert m_granted == [1], f"SUBACK for {matching_filter!r} granted {m_granted!r}, expected [1]"
    assert o_granted == [1], f"SUBACK for {other_filter!r} granted {o_granted!r}, expected [1]"

    payload = json.dumps({"marker": ctx.unique_name("p-"), "n": 1}).encode()
    info = matcher.publish(topic, payload, qos=1)
    deadline = time.time() + 30
    while time.time() < deadline and not info.is_published():
        time.sleep(0.1)
    assert info.is_published(), f"the broker never PUBACKed the publish to {topic!r}"

    delivered = _wait_for_inbox(
        m_state, lambda m: m.topic == topic, 1, 60,
        f"the matching filter {matching_filter!r} never received the publish on {topic!r}",
    )
    msg = delivered[0]
    assert msg.payload == payload, f"the broker delivered {msg.payload!r}, published {payload!r}"
    assert msg.topic == topic, f"delivered on topic {msg.topic!r}, published to {topic!r}"
    assert msg.dup is False, f"a first delivery carried the DUP flag: {msg.dup!r}"
    assert msg.qos == 1, f"delivered at qos {msg.qos!r}; both publish and subscribe were qos 1"
    assert msg.retain is False, f"a live (non-retained) publish carried the retain bit: {msg.retain!r}"

    # DIFFERENTIAL BARRIER: the non-matching subscription is proven LIVE by making it deliver
    # ten messages on a topic its own filter does cover. Only then is its emptiness on the
    # telemetry topic evidence of filter matching rather than of a slow subscription.
    for i in range(_BARRIER_PUBLISHES):
        matcher.publish(other_control, json.dumps({"seq": i}).encode(), qos=1)
    control_inbox = _wait_for_inbox(
        o_state, lambda m: m.topic == other_control, _BARRIER_PUBLISHES, 90,
        f"the barrier on {other_control!r} did not fully deliver",
    )
    seqs = sorted(json.loads(m.payload)["seq"] for m in control_inbox)
    assert seqs == list(range(_BARRIER_PUBLISHES)), f"the barrier delivered sequences {seqs!r}"

    other_inbox = _inbox(o_state, lambda m: m.topic != other_control)
    assert other_inbox == [], (
        f"the filter {other_filter!r} received traffic it does not match: "
        f"{[(m.topic, m.payload) for m in other_inbox]!r}"
    )
    assert len(control_inbox) == _BARRIER_PUBLISHES, (
        f"the barrier itself did not deliver: {len(control_inbox)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
