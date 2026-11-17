"""mqtt-topic-scoped-policy-confines-publish-to-its-resource-arn."""
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

CHECK = "mqtt-topic-scoped-policy-confines-publish-to-its-resource-arn"
GROUP = "mqtt-data-plane"
SERVICES = ["iot"]

#: Authorised publishes on the DENIED topic, to prove the topic itself is deliverable.
_BARRIER_PUBLISHES = 10


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


# ===== the check =====

@tags("axis:rejection", "cap:c6", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:native", "plane:data")
def run(ctx) -> None:
    """The broker enforces the TOPIC ARN in an `iot:Publish` grant, not just the action: the publish
    to `<base>/allowed` is PUBACKed and delivered, while the same session's publish to
    `<base>/denied` is refused and never arrives on a topic proven to deliver authorised traffic."""
    iot = ctx.client("iot")
    account = ctx.client("sts").get_caller_identity()["Account"]
    host = _ats_endpoint(ctx)

    workdir = tempfile.mkdtemp(prefix="sim2real-iot-mqtt-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))

    scenario = "mqtt-publish-resource-scope"
    base = f"sim2real/{ctx.unique_name('m')}"
    allowed = f"{base}/allowed"
    denied = f"{base}/denied"

    def arn(kind: str, rest: str) -> str:
        return f"arn:aws:iot:{ctx.region}:{account}:{kind}/{rest}"

    # The WATCHER is unscoped on purpose: it is the instrument, not the subject. It subscribes to
    # the whole base namespace and also supplies the barrier publishes on the denied topic.
    watcher_id = _provision_identity(
        ctx, iot, workdir,
        [{"Effect": "Allow",
          "Action": ["iot:Connect", "iot:Publish", "iot:Subscribe", "iot:Receive"],
          "Resource": "*"}],
        scenario, "watcher",
    )
    # The DEVICE differs in exactly one thing: iot:Publish is scoped to ONE topic ARN. Connect,
    # Subscribe and Receive are deliberately wide so that a CONNACK and a SUBACK both prove this
    # policy is already in force at the broker before the publish refusal is attributed to scope.
    device_id = _provision_identity(
        ctx, iot, workdir,
        [
            {"Effect": "Allow", "Action": "iot:Connect", "Resource": arn("client", "*")},
            {"Effect": "Allow", "Action": "iot:Publish", "Resource": arn("topic", allowed)},
            {"Effect": "Allow", "Action": "iot:Subscribe",
             "Resource": arn("topicfilter", f"{base}/#")},
            {"Effect": "Allow", "Action": "iot:Receive", "Resource": arn("topic", f"{base}/#")},
        ],
        scenario, "scoped",
    )

    watcher, watch_state = _mqtt_connect(
        ctx, host, watcher_id, ctx.unique_name("sim2real-iot-watch-"))
    assert watch_state["rc"] == 0, f"the watcher's CONNACK was {watch_state['rc']!r}, expected 0"
    watch_granted = _subscribe(watcher, watch_state, f"{base}/#", qos=1)
    assert watch_granted == [1], (
        f"the unscoped watcher's SUBACK on {base}/# granted {watch_granted!r}, expected [1]"
    )

    device, dev_state = _mqtt_connect(
        ctx, host, device_id, ctx.unique_name("sim2real-iot-scoped-"))
    assert dev_state["rc"] == 0, (
        f"the resource-scoped certificate could not connect: CONNACK {dev_state['rc']!r}"
    )
    dev_granted = _subscribe(device, dev_state, f"{base}/#", qos=1)
    assert dev_granted == [1], (
        f"the scoped certificate's SUBACK granted {dev_granted!r}; 128 would mean Subscribe was "
        f"refused too, which would make the publish refusal below unattributable to the ARN"
    )

    # POSITIVE CONTROL, first and in the SAME session: the in-scope topic works end to end.
    in_scope = json.dumps({"marker": ctx.unique_name("in-scope-")}).encode()
    _publish_acked(device, allowed, in_scope)
    _wait_for_payload(
        watch_state, allowed, in_scope, 60,
        f"the in-scope publish to {allowed!r} never reached the watcher",
    )

    # Break exactly one thing: the same certificate, action and session, one topic level sideways.
    out_of_scope = json.dumps({"marker": ctx.unique_name("out-of-scope-")}).encode()
    info = device.publish(denied, out_of_scope, qos=1)
    deadline = time.time() + 30
    while time.time() < deadline and not (info.is_published() or dev_state["disconnects"]):
        time.sleep(0.2)
    assert info.is_published() is False, (
        f"the broker PUBACKed a publish to {denied!r} from a certificate whose iot:Publish grant "
        f"names only {arn('topic', allowed)!r}"
    )
    assert dev_state["disconnects"], (
        f"the broker neither PUBACKed nor closed the session on an out-of-scope publish to "
        f"{denied!r}; one of the two must happen for the refusal to be observable"
    )
    # Stop the session before the barrier: paho re-sends the un-PUBACKed message on every
    # reconnect and the broker closes the connection again each time.
    _mqtt_close(device)

    # DIFFERENTIAL BARRIER: authorised publishes on the DENIED topic must all arrive before the
    # out-of-scope payload's absence counts as a refusal rather than as latency.
    for i in range(_BARRIER_PUBLISHES):
        watcher.publish(denied, json.dumps({"seq": i}).encode(), qos=1)
    deadline = time.time() + 90
    seqs: list = []
    while time.time() < deadline:
        seqs = sorted(json.loads(p)["seq"] for p in _payloads(watch_state, denied) if b"seq" in p)
        if len(seqs) >= _BARRIER_PUBLISHES:
            break
        time.sleep(0.2)
    assert seqs == list(range(_BARRIER_PUBLISHES)), (
        f"the barrier on {denied!r} delivered sequences {seqs!r}, expected "
        f"{list(range(_BARRIER_PUBLISHES))!r}"
    )
    assert out_of_scope not in _payloads(watch_state, denied), (
        f"a publish outside the certificate's topic ARN scope was delivered to {denied!r}: "
        f"{_payloads(watch_state, denied)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
