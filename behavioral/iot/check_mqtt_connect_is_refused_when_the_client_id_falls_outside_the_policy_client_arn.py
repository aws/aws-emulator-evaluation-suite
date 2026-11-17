"""mqtt-connect-is-refused-when-the-client-id-falls-outside-the-policy-client-arn."""
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

CHECK = "mqtt-connect-is-refused-when-the-client-id-falls-outside-the-policy-client-arn"
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


def _connect_once(ctx, host: str, identity: dict, client_id: str, wait_s: int = 20) -> dict:
    """ONE CONNECT attempt, with no retry, reporting exactly how the broker answered.

    Deliberately not ``_mqtt_connect``: that helper retries until CONNACK rc=0 because it is used
    where a connection is a precondition. Here the answer IS the subject, so a retry loop would
    hide it, and the outcome has to distinguish a CONNACK carrying a refusal code from a transport
    the broker closed without answering at all.
    """
    import paho.mqtt.client as mqtt

    state = {"rc": None, "closed": threading.Event(), "answered": threading.Event()}

    def on_connect(_c, _u, _flags, rc):
        state["rc"] = int(rc)
        state["answered"].set()

    def on_disconnect(_c, _u, rc):
        state["closed"].set()
        state["answered"].set()

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=client_id, clean_session=True)
    client.tls_set(cert_reqs=ssl.CERT_NONE, certfile=identity["cert_path"], keyfile=identity["key_path"],
                   tls_version=ssl.PROTOCOL_TLS_CLIENT)
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    try:
        client.connect(*ctx.endpoint_host(host, 8883), keepalive=30)
        client.loop_start()
        state["answered"].wait(timeout=wait_s)
    except Exception as exc:  # noqa: BLE001 - the transport failure IS one of the outcomes
        return {"outcome": "transport-error", "rc": None, "detail": repr(exc)}
    finally:
        try:
            client.loop_stop()
            client.disconnect()
        except Exception:  # noqa: BLE001
            pass
    if state["rc"] == 0:
        return {"outcome": "accepted", "rc": 0, "detail": "CONNACK rc=0"}
    if state["rc"] is not None:
        return {"outcome": "connack-refusal", "rc": state["rc"],
                "detail": f"CONNACK rc={state['rc']}"}
    if state["closed"].is_set():
        return {"outcome": "closed-without-connack", "rc": None,
                "detail": "transport closed with no CONNACK"}
    return {"outcome": "no-answer", "rc": None, "detail": f"nothing within {wait_s}s"}


# ===== the check =====

@tags("axis:rejection", "cap:c6", "concern:data-plane", "concern:negative-classes",
      "dp:native", "plane:data")
def run(ctx) -> None:
    """The broker enforces the CLIENT ARN in an `iot:Connect` grant during the MQTT handshake: the
    named client id connects and its session works end to end, while the same certificate
    presenting any other client id is refused every time over a bounded window."""
    iot = ctx.client("iot")
    account = ctx.client("sts").get_caller_identity()["Account"]
    host = _ats_endpoint(ctx)

    workdir = tempfile.mkdtemp(prefix="sim2real-iot-mqtt-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))

    scenario = "mqtt-connect-client-scope"
    topic = f"sim2real/{ctx.unique_name('m')}/scoped"
    allowed_client = ctx.unique_name("sim2real-iot-allowed-")
    denied_client = ctx.unique_name("sim2real-iot-denied-")

    # Break exactly one thing: iot:Connect names ONE client ARN. Publish, Subscribe and Receive are
    # unscoped, so a refusal can only be the Connect grant.
    identity = _provision_identity(
        ctx, iot, workdir,
        [
            {"Effect": "Allow", "Action": "iot:Connect",
             "Resource": f"arn:aws:iot:{ctx.region}:{account}:client/{allowed_client}"},
            {"Effect": "Allow", "Action": ["iot:Publish", "iot:Subscribe", "iot:Receive"],
             "Resource": "*"},
        ],
        scenario, "scoped",
    )

    # POSITIVE CONTROL, first: the named client id connects AND its session really works. Proving
    # the session functional is what makes the refusal below a client-id decision rather than a
    # policy that had not propagated -- and the retry inside _mqtt_connect is the propagation wait.
    allowed, allowed_state = _mqtt_connect(ctx, host, identity, allowed_client)
    assert allowed_state["rc"] == 0, (
        f"the in-scope client id {allowed_client!r} was refused: CONNACK {allowed_state['rc']!r}"
    )
    granted = _subscribe(allowed, allowed_state, topic, qos=1)
    assert granted == [1], f"the in-scope client's SUBACK on {topic!r} granted {granted!r}"
    body = json.dumps({"marker": ctx.unique_name("in-scope-")}).encode()
    _publish_acked(allowed, topic, body)
    _wait_for_payload(
        allowed_state, topic, body, 60,
        f"the in-scope client id's own session could not round-trip a message on {topic!r}, so "
        f"the policy is not yet usable and the refusal below would be unattributable",
    )

    # The SAME certificate, the SAME policy, one different client id. Repeated over a bounded
    # window: a single refusal could be a transient, whereas an unbroken run of them cannot.
    outcomes = []
    deadline = time.time() + 60
    while time.time() < deadline and len(outcomes) < 3:
        outcomes.append(_connect_once(ctx, host, identity, denied_client))
        time.sleep(2)
    assert len(outcomes) == 3, f"only {len(outcomes)!r} connect attempts completed: {outcomes!r}"
    assert not any(o["outcome"] == "accepted" for o in outcomes), (
        f"the broker accepted client id {denied_client!r} from a certificate whose iot:Connect "
        f"grant names only {allowed_client!r}; attempts were {outcomes!r}"
    )
    # MEASURED shape of the refusal, asserted exactly rather than as "something went wrong": AWS
    # IoT closes the TLS transport during the handshake and never sends a CONNACK.
    shapes = sorted({o["outcome"] for o in outcomes})
    assert shapes == ["closed-without-connack"], (
        f"the out-of-scope CONNECT was refused as {shapes!r}; the measured AWS IoT behaviour is a "
        f"transport close with no CONNACK. Attempts were {outcomes!r}"
    )
    # EFFECT ABSENT: the refused client id never became a session, so it cannot have subscribed.
    # The in-scope client is still live and still receiving, which is the differential barrier.
    sentinel = json.dumps({"marker": ctx.unique_name("still-live-")}).encode()
    _publish_acked(allowed, topic, sentinel)
    _wait_for_payload(
        allowed_state, topic, sentinel, 60,
        "the in-scope session stopped receiving during the refused attempts, so the refusals "
        "cannot be attributed to the client-id scope",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
