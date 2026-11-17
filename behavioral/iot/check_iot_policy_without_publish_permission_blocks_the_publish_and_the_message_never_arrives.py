"""iot-policy-without-publish-permission-blocks-the-publish-and-the-message-never-arrives."""
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

CHECK = "iot-policy-without-publish-permission-blocks-the-publish-and-the-message-never-arrives"
GROUP = 'mqtt-rejection'
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
    proving THIS certificate's policy is in force.
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


def _payloads(state: dict) -> list[bytes]:
    with state["lock"]:
        return [m.payload for m in state["messages"]]


def _wait_for_payloads(state: dict, count: int, timeout_s: int, what: str) -> list[bytes]:
    deadline = time.time() + timeout_s
    got: list[bytes] = []
    while time.time() < deadline:
        got = _payloads(state)
        if len(got) >= count:
            return got
        time.sleep(0.2)
    raise AssertionError(f"{what}: only {len(got)!r} of {count!r} arrived in {timeout_s}s: {got!r}")


@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:eventing",
    "dp:native",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A certificate granted Connect/Subscribe/Receive but not Publish connects and subscribes,
    yet its PUBLISH never reaches an authorised subscriber (held against authorised traffic on the
    same topic); adding iot:Publish makes the same publish arrive."""
    iot = ctx.client("iot")
    host = _ats_endpoint(ctx)

    workdir = tempfile.mkdtemp(prefix="sim2real-iot-mqtt-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))

    scenario = "mqtt-publish-denied"
    full = ["iot:Connect", "iot:Publish", "iot:Subscribe", "iot:Receive"]
    identity_a = _provision_identity(ctx, iot, workdir, full, scenario, "authorised")
    # Break exactly one thing: identity B's policy omits iot:Publish and nothing else.
    identity_b = _provision_identity(
        ctx, iot, workdir, ["iot:Connect", "iot:Subscribe", "iot:Receive"], scenario, "nopublish")

    topic = f"sim2real/{ctx.unique_name('m')}/shared"

    subscriber, sub_state = _mqtt_connect(
        ctx, host, identity_a, ctx.unique_name("sim2real-iot-sub-"))
    granted = _subscribe(subscriber, sub_state, topic, qos=1)
    assert granted == [1], f"the authorised subscriber's SUBACK granted {granted!r}, expected [1]"

    publisher_b, b_state = _mqtt_connect(
        ctx, host, identity_b, ctx.unique_name("sim2real-iot-nopub-"))
    # CONNACK 0 and a granted SUBACK both come from policy B, so both prove policy B is already
    # in force at the broker. That is what makes the publish refusal below a decision rather
    # than a policy that had not propagated yet.
    assert b_state["rc"] == 0, f"the no-publish certificate could not even connect: {b_state['rc']!r}"
    b_granted = _subscribe(publisher_b, b_state, topic, qos=1)
    assert b_granted == [1], (
        f"the no-publish certificate's SUBACK granted {b_granted!r}; 128 means Subscribe was "
        f"refused too, which would make the publish refusal unattributable"
    )

    unauthorized = json.dumps({"marker": ctx.unique_name("denied-")}).encode()
    info = publisher_b.publish(topic, unauthorized, qos=1)
    deadline = time.time() + 30
    while time.time() < deadline and not (info.is_published() or b_state["disconnects"]):
        time.sleep(0.2)
    assert info.is_published() is False, (
        f"the broker PUBACKed a publish from a certificate with no iot:Publish permission "
        f"(topic {topic!r})"
    )
    assert b_state["disconnects"], (
        "the broker neither PUBACKed nor closed the session on an unauthorised publish; "
        "one of the two must happen for the refusal to be observable"
    )
    # Stop the session before the barrier: paho re-sends the un-PUBACKed message on every
    # reconnect, and the broker closes the connection again each time.
    _mqtt_close(publisher_b)

    # DIFFERENTIAL BARRIER: ten authorised publishes on the SAME topic must all arrive before
    # the unauthorised message's absence counts as a refusal rather than as latency.
    for i in range(_BARRIER_PUBLISHES):
        subscriber.publish(topic, json.dumps({"seq": i}).encode(), qos=1)
    inbox = _wait_for_payloads(
        sub_state, _BARRIER_PUBLISHES, 90, f"the barrier on {topic!r} did not fully deliver")
    seqs = sorted(json.loads(p)["seq"] for p in inbox if b"seq" in p)
    assert seqs == list(range(_BARRIER_PUBLISHES)), f"the barrier delivered sequences {seqs!r}"
    assert unauthorized not in inbox, (
        f"a publish from a certificate with no iot:Publish permission was delivered: {inbox!r}"
    )

    # POSITIVE CONTROL: grant iot:Publish to the SAME certificate through a new default policy
    # version and require the same publish to arrive. This is what proves the topic, the
    # subscription and the certificate were all fine and only the missing action suppressed it.
    iot.create_policy_version(
        policyName=identity_b["policy"],
        policyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": full, "Resource": "*"}],
        }),
        setAsDefault=True,
    )
    control = json.dumps({"marker": ctx.unique_name("granted-")}).encode()
    regrant, regrant_state = _mqtt_connect(
        ctx, host, identity_b, ctx.unique_name("sim2real-iot-regrant-"))
    assert regrant_state["rc"] == 0, f"the regranted certificate could not connect: {regrant_state['rc']!r}"
    deadline = time.time() + 180
    arrived = False
    attempts = 0
    while time.time() < deadline and not arrived:
        attempts += 1
        regrant.publish(topic, control, qos=1)
        inner = time.time() + 10
        while time.time() < inner:
            if control in _payloads(sub_state):
                arrived = True
                break
            time.sleep(0.3)
    assert arrived, (
        f"granting iot:Publish did not make the same publish arrive after {attempts!r} attempts; "
        f"the subscriber held {_payloads(sub_state)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
