"""mqtt-topic-scoped-policy-confines-subscribe-to-its-topicfilter-arn."""
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

CHECK = "mqtt-topic-scoped-policy-confines-subscribe-to-its-topicfilter-arn"
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


# ===== the check =====

@tags("axis:rejection", "cap:c6", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:native", "plane:data")
def run(ctx) -> None:
    """The broker enforces the TOPICFILTER ARN in an `iot:Subscribe` grant: the in-scope filter is
    granted QoS 1 and delivers, an out-of-scope SUBSCRIBE gets no SUBACK and the session is closed,
    and a publish to that topic reaches an unscoped subscriber but never this client."""
    iot = ctx.client("iot")
    account = ctx.client("sts").get_caller_identity()["Account"]
    host = _ats_endpoint(ctx)

    workdir = tempfile.mkdtemp(prefix="sim2real-iot-mqtt-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))

    scenario = "mqtt-subscribe-resource-scope"
    base = f"sim2real/{ctx.unique_name('m')}"
    allowed = f"{base}/allowed"
    denied = f"{base}/denied"

    def arn(kind: str, rest: str) -> str:
        return f"arn:aws:iot:{ctx.region}:{account}:{kind}/{rest}"

    # The PUBLISHER is unscoped on purpose: it is the instrument, not the subject.
    pub_id = _provision_identity(
        ctx, iot, workdir,
        [{"Effect": "Allow",
          "Action": ["iot:Connect", "iot:Publish", "iot:Subscribe", "iot:Receive"],
          "Resource": "*"}],
        scenario, "publisher",
    )
    # The DEVICE differs in EXACTLY ONE thing: iot:Subscribe names ONE topicfilter ARN. Connect,
    # Publish and Receive are all left unscoped on purpose -- narrowing Receive too would make a
    # non-delivery on the denied topic ambiguous between the two grants, which is precisely the
    # confound this check exists to exclude.
    device_id = _provision_identity(
        ctx, iot, workdir,
        [
            {"Effect": "Allow", "Action": ["iot:Connect", "iot:Publish", "iot:Receive"],
             "Resource": "*"},
            {"Effect": "Allow", "Action": "iot:Subscribe",
             "Resource": arn("topicfilter", allowed)},
        ],
        scenario, "scoped",
    )

    publisher, pub_state = _mqtt_connect(
        ctx, host, pub_id, ctx.unique_name("sim2real-iot-pub-"))
    assert pub_state["rc"] == 0, f"the publisher's CONNACK was {pub_state['rc']!r}, expected 0"

    device, dev_state = _mqtt_connect(
        ctx, host, device_id, ctx.unique_name("sim2real-iot-scoped-"))
    assert dev_state["rc"] == 0, (
        f"the resource-scoped certificate could not connect: CONNACK {dev_state['rc']!r}"
    )

    # POSITIVE CONTROL, first and in the SAME session: the in-scope filter is granted and live.
    in_granted = _subscribe(device, dev_state, allowed, qos=1)
    assert in_granted == [1], (
        f"the in-scope SUBACK on {allowed!r} granted {in_granted!r}, expected [1]; the grant "
        f"names exactly {arn('topicfilter', allowed)!r}"
    )
    first = json.dumps({"marker": ctx.unique_name("in-scope-")}).encode()
    _publish_acked(publisher, allowed, first)
    _wait_for_payload(
        dev_state, allowed, first, 60,
        f"the in-scope subscription on {allowed!r} never received a published payload",
    )

    # Publish to the out-of-scope topic while this session is still live, then a sentinel to the
    # in-scope one. The sentinel's arrival is the ordering barrier: it proves the session was
    # receiving at the moment the out-of-scope message was on the wire.
    unheard = json.dumps({"marker": ctx.unique_name("unheard-")}).encode()
    _publish_acked(publisher, denied, unheard)
    sentinel = json.dumps({"marker": ctx.unique_name("sentinel-")}).encode()
    _publish_acked(publisher, allowed, sentinel)
    _wait_for_payload(
        dev_state, allowed, sentinel, 60,
        "the ordering sentinel on the granted filter did not arrive, so the out-of-scope topic's "
        "empty inbox could not be read as a refusal",
    )

    # Break exactly one thing: subscribe one topic level sideways on the SAME live session.
    # MEASURED on real AWS: the broker does NOT answer an out-of-scope SUBSCRIBE with SUBACK 0x80.
    # It sends no SUBACK at all and closes the TCP session. Both halves of that are asserted --
    # the absent SUBACK and the close -- because either one alone is also what a lost packet or an
    # idle timeout looks like.
    closes_before = len(dev_state["disconnects"])
    _res, mid = device.subscribe(denied, qos=1)
    deadline = time.time() + 60
    out_granted = None
    closed = False
    while time.time() < deadline:
        with dev_state["lock"]:
            out_granted = dev_state["suback"].get(mid)
        if out_granted is not None:
            break
        if len(dev_state["disconnects"]) > closes_before:
            closed = True
            break
        time.sleep(0.2)
    assert out_granted is None, (
        f"the broker SUBACKed an out-of-scope SUBSCRIBE to {denied!r} with granted QoS "
        f"{out_granted!r}; the certificate's iot:Subscribe grant names only "
        f"{arn('topicfilter', allowed)!r}"
    )
    assert closed, (
        f"the broker neither SUBACKed nor closed the session on an out-of-scope SUBSCRIBE to "
        f"{denied!r}; one of the two must happen for the refusal to be observable. Disconnect "
        f"codes seen: {dev_state['disconnects']!r}"
    )
    # Stop the session here: paho's network loop auto-reconnects after an unexpected close, and a
    # reconnect would keep re-attempting nothing useful while muddying the inbox assertion below.
    _mqtt_close(device)

    # EFFECT ABSENT over the whole session: the refused topic never delivered a single message to
    # this client, including the one published to it while the session was still live.
    assert _payloads(dev_state, denied) == [], (
        f"a topic whose SUBSCRIBE the broker refused still delivered messages to the scoped "
        f"client: {_payloads(dev_state, denied)!r}"
    )

    # DELIVERABILITY CONTROL: the same publishes reach an UNSCOPED subscriber on the same topic,
    # so the device's silence is the authorisation decision and not an undeliverable topic.
    checker, check_state = _mqtt_connect(
        ctx, host, pub_id, ctx.unique_name("sim2real-iot-check-"))
    checker_granted = _subscribe(checker, check_state, denied, qos=1)
    assert checker_granted == [1], (
        f"the unscoped checker's SUBACK on {denied!r} granted {checker_granted!r}, expected [1]"
    )
    again = json.dumps({"marker": ctx.unique_name("deliverable-")}).encode()
    _publish_acked(publisher, denied, again)
    _wait_for_payload(
        check_state, denied, again, 60,
        f"{denied!r} did not deliver to an UNSCOPED subscriber either, so the topic itself is "
        f"the problem and the refusal above is unattributable to the topicfilter ARN",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
