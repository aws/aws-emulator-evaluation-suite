"""inactive-certificate-is-refused-at-the-mqtt-handshake."""
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

CHECK = "inactive-certificate-is-refused-at-the-mqtt-handshake"
GROUP = "certificate-lifecycle"
SERVICES = ["iot"]

# How long a certificate status change is allowed to take to reach the broker's authenticator.
_STATUS_PROPAGATION_S = 120.0
# Consecutive refused CONNECT attempts required before the refusal is believed.
_FREEZE_ATTEMPTS = 3
# The delivery-absence hold is floored here so a merely slower broker cannot read as having blocked.
_MIN_ABSENCE_HOLD_S = 15.0


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c6",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """A certificate's ACTIVE/INACTIVE status is enforced at the MQTT handshake, not just stored.

    INACTIVE material never reaches CONNACK rc=0 and its publish is withheld while an ACTIVE twin
    connects; restoring ACTIVE makes the identical connect-and-publish work again.
    """
    iot = ctx.client("iot")
    host = _ats_endpoint(ctx)

    workdir = tempfile.mkdtemp(prefix="sim2real-iot-certstatus-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))

    scenario = "certificate-status-gates-mqtt"
    policy = _create_policy(
        ctx, iot, ["iot:Connect", "iot:Publish", "iot:Subscribe", "iot:Receive"], scenario)
    subject = _provision_certificate(ctx, iot, workdir, policy, "subject")
    twin = _provision_certificate(ctx, iot, workdir, policy, "twin")

    topic = f"sim2real/{ctx.unique_name('cs')}/telemetry"

    # ---- BEAT 1: positive control. The whole wiring works while the subject is ACTIVE.
    sub_client, sub_state = _connect_until_accepted(
        ctx, host, twin, ctx.unique_name("sim2real-iot-cs-sub-"), _STATUS_PROPAGATION_S)
    granted = _subscribe(sub_client, sub_state, topic, qos=1)
    assert granted == [1], (
        f"SUBACK for {topic!r} granted {granted!r}, expected [1]; 128 means the subscription was "
        "refused and every absence below would be unattributable"
    )

    t0 = time.monotonic()
    # _publish_and_expect RAISES if the message never arrives, so this call IS the positive control;
    # there is deliberately no `assert result is not None` after it, which could not fail.
    _publish_and_expect(
        ctx, host, subject, topic, sub_state, "active-1",
        "an ACTIVE certificate's publish did not reach the subscriber; the wiring is broken before "
        "the subject of this check is even touched",
    )
    delivery_latency = time.monotonic() - t0

    active_status = iot.describe_certificate(
        certificateId=subject["cert_id"])["certificateDescription"]["status"]
    assert active_status == "ACTIVE", (
        f"the subject certificate's status was {active_status!r} before the check broke anything, "
        "expected 'ACTIVE'"
    )

    # ---- BEAT 2: break exactly one thing. The policy, the topic and the twin are untouched.
    iot.update_certificate(certificateId=subject["cert_id"], newStatus="INACTIVE")

    inactive_status = iot.describe_certificate(
        certificateId=subject["cert_id"])["certificateDescription"]["status"]
    assert inactive_status == "INACTIVE", (
        f"DescribeCertificate reported {inactive_status!r} after UpdateCertificate set INACTIVE; "
        "an independent read must confirm the ONE thing this check broke"
    )

    # ---- BEAT 3: the specific refusal, with the twin proving the broker is otherwise healthy.
    delivered_before = len(_inbox(sub_state, lambda m: m.topic == topic))

    refusals = _await_sustained_refusal(ctx, host, subject, _STATUS_PROPAGATION_S)
    assert len(refusals) >= _FREEZE_ATTEMPTS, (
        f"only {len(refusals)!r} consecutive CONNECT attempts were refused, expected at least "
        f"{_FREEZE_ATTEMPTS!r}"
    )
    for attempt in refusals:
        assert attempt["rc"] != 0, (
            f"an INACTIVE certificate reached CONNACK rc={attempt['rc']!r} on {host}:8883; "
            "UpdateCertificate INACTIVE must stop the certificate authenticating"
        )
        assert attempt["error"] is not None or attempt["disconnects"], (
            "the broker neither returned a CONNACK nor produced an error or a disconnect for an "
            f"INACTIVE certificate ({attempt!r}); one of those must happen for the refusal to be "
            "observable rather than a silent hang"
        )

    twin_client, twin_state = _connect_until_accepted(
        ctx, host, twin, ctx.unique_name("sim2real-iot-cs-twincheck-"), 60.0)
    assert twin_state["rc"] == 0, (
        f"the still-ACTIVE twin certificate could not connect either (rc={twin_state['rc']!r}), so "
        "the subject's refusal is not attributable to its status — the broker is refusing everything"
    )
    _mqtt_close(twin_client)

    # ---- BEAT 4: effect absent at the destination, bounded by a control on the same wiring.
    # The subscriber's OWN publish on the SAME topic must arrive during the same window, so an
    # emptiness caused by a dead subscription cannot be mistaken for enforcement.
    barrier_payload = json.dumps({"marker": ctx.unique_name("barrier-")}).encode()
    info = sub_client.publish(topic, barrier_payload, qos=1)
    deadline = time.time() + 30
    while time.time() < deadline and not info.is_published():
        time.sleep(0.1)
    assert info.is_published(), f"the broker never PUBACKed the barrier publish to {topic!r}"
    _wait_for_inbox(
        sub_state, lambda m: m.payload == barrier_payload, 1, 60,
        "the subscriber's own barrier publish never came back, so the subscription is not live and "
        "the absence assertion below would prove nothing",
    )

    hold_s = max(_FREEZE_ATTEMPTS * delivery_latency, _MIN_ABSENCE_HOLD_S)
    _hold(hold_s)
    after = _inbox(sub_state, lambda m: m.topic == topic and m.payload != barrier_payload)
    assert len(after) == delivered_before, (
        f"the subscriber received {len(after)!r} non-barrier messages on {topic!r} after the "
        f"subject certificate went INACTIVE, expected the pre-existing {delivered_before!r}; "
        f"newest was {[m.payload for m in after[delivered_before:]]!r}"
    )

    # ---- BEAT 5: restore the one thing that was broken.
    iot.update_certificate(certificateId=subject["cert_id"], newStatus="ACTIVE")
    restored_status = iot.describe_certificate(
        certificateId=subject["cert_id"])["certificateDescription"]["status"]
    assert restored_status == "ACTIVE", (
        f"DescribeCertificate reported {restored_status!r} after UpdateCertificate restored ACTIVE"
    )

    # ---- BEAT 6: the identical call now succeeds, end to end, at the destination.
    restored = _publish_and_expect(
        ctx, host, subject, topic, sub_state, "active-2",
        "re-activating the certificate did not make the identical connect-and-publish work again; "
        "the refusal in beat 3 is therefore not attributable to the status change",
        connect_timeout_s=_STATUS_PROPAGATION_S,
    )
    assert restored.topic == topic, (
        f"the restored publish was delivered on {restored.topic!r}, published to {topic!r}"
    )


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


def _hold(seconds: float) -> None:
    """A calibrated absence window derived from a latency measured on this wiring in this run."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        time.sleep(0.5)


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


def _create_policy(ctx, iot, actions: list[str], scenario: str) -> str:
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
    return policy


def _provision_certificate(ctx, iot, workdir: str, policy: str, label: str) -> dict:
    """A certificate + key pair on disk, attached to *policy*, so only STATUS distinguishes them."""
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
    return {"cert_id": cert_id, "cert_arn": cert_arn,
            "cert_path": cert_path, "key_path": key_path, "label": label}


def _new_client(ctx, identity: dict, client_id: str):
    """One paho client and its observation state. Never auto-reconnects.

    reconnect_delay_set pushes the first background reconnect far past this check's own deadlines,
    so a refused CONNECT stays refused instead of paho quietly re-attempting it and turning a
    single-attempt probe into an unbounded retry loop.
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
    client.tls_set(certfile=identity["cert_path"], keyfile=identity["key_path"],
                   tls_version=ssl.PROTOCOL_TLS_CLIENT)
    client.reconnect_delay_set(min_delay=10_000, max_delay=10_000)
    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_message = on_message
    client.on_disconnect = on_disconnect
    ctx.on_cleanup(lambda: _mqtt_close(client))
    return client, state


# tls-subject: the check asserts certificate state decides the mutual-TLS handshake.
def _connect_once(ctx, host: str, identity: dict, client_id: str, wait_s: float = 20.0):
    """ONE CONNECT attempt. Returns (client, state); state['rc'] is None if no CONNACK arrived."""
    client, state = _new_client(ctx, identity, client_id)
    state["error"] = None
    try:
        client.connect(*ctx.endpoint_host(host, 8883), keepalive=30)
        client.loop_start()
        state["connected"].wait(timeout=wait_s)
    except (OSError, ssl.SSLError) as exc:
        state["error"] = repr(exc)
        client.loop_stop()
    return client, state


def _connect_until_accepted(ctx, host: str, identity: dict, client_id: str, timeout_s: float):
    """Bounded retry until CONNACK rc=0; RAISES on timeout. Policy attachment is eventually
    consistent at the broker, so a successful CONNACK is also the barrier proving it is in force."""
    deadline = time.time() + timeout_s
    last = None
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        client, state = _connect_once(ctx, host, identity, f"{client_id}{attempt}")
        if state["rc"] == 0:
            return client, state
        last = {"rc": state["rc"], "error": state["error"]}
        _mqtt_close(client)
        time.sleep(3)
    raise AssertionError(
        f"{identity['label']!r} never got CONNACK rc=0 from {host}:8883 within {timeout_s}s over "
        f"{attempt!r} attempts; last result {last!r}"
    )


def _await_sustained_refusal(ctx, host: str, identity: dict, timeout_s: float) -> list[dict]:
    """Poll until a CONNECT is refused, then require _FREEZE_ATTEMPTS consecutive refusals.

    Certificate status propagates to the authenticator with lag, so a single early attempt could
    still succeed; and a single late refusal could be a transient. RAISES on timeout rather than
    returning whatever it saw, and the returned attempts are asserted on by the caller.
    """
    deadline = time.time() + timeout_s
    run_of_refusals: list[dict] = []
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        client, state = _connect_once(
            ctx, host, identity, f"{identity['label']}-refuse-{attempt}-")
        result = {"rc": state["rc"], "error": state["error"],
                  "disconnects": list(state["disconnects"])}
        _mqtt_close(client)
        if result["rc"] == 0:
            run_of_refusals = []
            time.sleep(5)
            continue
        run_of_refusals.append(result)
        if len(run_of_refusals) >= _FREEZE_ATTEMPTS:
            return run_of_refusals
        time.sleep(2)
    raise AssertionError(
        f"an INACTIVE certificate was still accepted (or refused only intermittently) after "
        f"{timeout_s}s and {attempt!r} CONNECT attempts; longest refusal run was "
        f"{len(run_of_refusals)!r}, needed {_FREEZE_ATTEMPTS!r}"
    )


def _publish_and_expect(ctx, host, identity, topic, sub_state, label, what,
                        connect_timeout_s: float = 60.0):
    """Connect *identity*, publish one unique payload, and return the message the SUBSCRIBER got."""
    client, _state = _connect_until_accepted(
        ctx, host, identity, ctx.unique_name(f"sim2real-iot-cs-{label}-"), connect_timeout_s)
    payload = json.dumps({"marker": ctx.unique_name(f"{label}-")}).encode()
    info = client.publish(topic, payload, qos=1)
    deadline = time.time() + 30
    while time.time() < deadline and not info.is_published():
        time.sleep(0.1)
    assert info.is_published(), f"the broker never PUBACKed the {label!r} publish to {topic!r}"
    hits = _wait_for_inbox(sub_state, lambda m: m.payload == payload, 1, 60, what)
    _mqtt_close(client)
    return hits[0]


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
