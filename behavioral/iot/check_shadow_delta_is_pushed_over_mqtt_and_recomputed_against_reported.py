"""shadow-delta-is-pushed-over-mqtt-and-recomputed-against-reported."""
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

CHECK = "shadow-delta-is-pushed-over-mqtt-and-recomputed-against-reported"
GROUP = "shadow"
SERVICES = ["iot"]

# The absence leg holds for at least this long even if the measured delta latency is tiny, so a
# broker that is merely slower than this run's positive control cannot read as "blocked".
_MIN_ABSENCE_HOLD_S = 15.0
# Consecutive identical reads required before an absence is believed (B6 freeze detector).
_FREEZE_READS = 3


@tags(
    "axis:negative-delivery",
    "cap:c2",
    "cap:c6",
    "concern:data-plane",
    "concern:eventing",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """The shadow delta is a live MQTT push that is RECOMPUTED against reported, not accumulated.

    Desired writes push deltas with every differing leaf, a converging `reported` write pushes
    /update/accepted and /update/documents but no delta, and a later delta holds only what differs.
    """
    iot = ctx.client("iot")
    data = ctx.client("iot-data")

    host = _ats_endpoint(ctx)

    workdir = tempfile.mkdtemp(prefix="sim2real-iot-shadow-mqtt-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))

    scenario = "shadow-delta-over-mqtt"
    thing = ctx.unique_name("sim2real-iot-shadowthing-")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing))
    ctx.on_cleanup(lambda: _delete_shadow(data, thing))

    identity = _provision_identity(
        ctx, iot, workdir,
        ["iot:Connect", "iot:Subscribe", "iot:Receive", "iot:Publish"],
        scenario, "device",
    )

    prefix = f"$aws/things/{thing}/shadow"
    t_delta = f"{prefix}/update/delta"
    t_accepted = f"{prefix}/update/accepted"
    t_documents = f"{prefix}/update/documents"

    client, state = _mqtt_connect(ctx, host, identity, ctx.unique_name("sim2real-iot-shadowsub-"))
    assert state["rc"] == 0, f"the shadow subscriber's CONNACK was rc={state['rc']!r}, expected 0"

    for topic in (t_delta, t_accepted, t_documents):
        granted = _subscribe(client, state, topic, qos=1)
        assert granted == [1], (
            f"SUBACK for the reserved shadow topic {topic!r} granted {granted!r}, expected [1]; "
            "128 means the broker refused the subscription and every absence below would be "
            "unattributable"
        )

    # ---- Leg 1: a desired write pushes a delta, and its latency calibrates the absence window.
    t0 = time.monotonic()
    data.update_thing_shadow(
        thingName=thing,
        payload=json.dumps({"state": {"desired": {"alpha": 1}}}).encode(),
    )
    first = _wait_for_inbox(
        state, lambda m: m.topic == t_delta, 1, 60,
        f"an accepted desired-only UpdateThingShadow published no delta on {t_delta!r}",
    )
    delta_latency = time.monotonic() - t0
    doc1 = json.loads(first[0].payload)
    assert doc1["state"] == {"alpha": 1}, (
        f"the first delta carried state {doc1['state']!r}, expected {{'alpha': 1}} — the only leaf "
        "present in desired and absent from reported"
    )
    v1 = doc1["version"]

    # ---- Leg 2: THE STICKY RULE. The delta carries every differing leaf, not just the new one.
    data.update_thing_shadow(
        thingName=thing,
        payload=json.dumps({"state": {"desired": {"beta": 2}}}).encode(),
    )
    second = _wait_for_inbox(
        state, lambda m: m.topic == t_delta, 2, 60,
        f"the second desired write published no second delta on {t_delta!r}",
    )
    doc2 = json.loads(second[1].payload)
    assert doc2["state"] == {"alpha": 1, "beta": 2}, (
        f"the second delta carried state {doc2['state']!r}, expected {{'alpha': 1, 'beta': 2}}: a "
        "delta holds EVERY desired leaf that differs from reported, including leaves already "
        "stored before this update, not an echo of the just-written keys"
    )
    v2 = doc2["version"]
    assert v2 > v1, (
        f"the shadow version did not advance across two accepted updates: delta 1 reported {v1!r}, "
        f"delta 2 reported {v2!r}"
    )

    # ---- Leg 3: convergence produces /update/accepted and /update/documents but NO delta.
    # The absence is bounded by TWO controls on the SAME subscription, never by a bare sleep:
    #   (a) a STRUCTURAL barrier — the /update/documents message for this very update proves the
    #       service processed it and that this client is still receiving broker pushes; and
    #   (b) a CALIBRATED window of 3x the delta latency measured in leg 1 on this exact wiring.
    deltas_before = len(_inbox(state, lambda m: m.topic == t_delta))
    accepted_before = len(_inbox(state, lambda m: m.topic == t_accepted))
    documents_before = len(_inbox(state, lambda m: m.topic == t_documents))

    data.update_thing_shadow(
        thingName=thing,
        payload=json.dumps({"state": {"reported": {"alpha": 1, "beta": 2}}}).encode(),
    )
    docs = _wait_for_inbox(
        state, lambda m: m.topic == t_documents, documents_before + 1, 60,
        f"the converging reported write published nothing on {t_documents!r}, so nothing proves "
        "the service processed it and the delta absence below would be unattributable",
    )
    accepted = _wait_for_inbox(
        state, lambda m: m.topic == t_accepted, accepted_before + 1, 60,
        f"the converging reported write published nothing on {t_accepted!r}",
    )
    acc_doc = json.loads(accepted[-1].payload)
    assert acc_doc["state"]["reported"] == {"alpha": 1, "beta": 2}, (
        f"/update/accepted echoed reported {acc_doc['state']['reported']!r}, expected "
        "{'alpha': 1, 'beta': 2}"
    )

    documents = json.loads(docs[-1].payload)
    assert documents["current"]["state"]["reported"] == {"alpha": 1, "beta": 2}, (
        "/update/documents current.state.reported was "
        f"{documents['current']['state'].get('reported')!r}, expected {{'alpha': 1, 'beta': 2}}"
    )
    prev_reported = documents["previous"]["state"].get("reported")
    assert prev_reported != {"alpha": 1, "beta": 2}, (
        "/update/documents reported the same value for previous and current "
        f"({prev_reported!r}); previous must be the pre-update document, and reported did not "
        "exist before this update"
    )
    assert documents["current"]["state"]["desired"] == {"alpha": 1, "beta": 2}, (
        "/update/documents current.state.desired was "
        f"{documents['current']['state'].get('desired')!r}, expected the unchanged desired "
        "{'alpha': 1, 'beta': 2}"
    )

    hold_s = max(_FREEZE_READS * delta_latency, _MIN_ABSENCE_HOLD_S)
    _assert_count_frozen(
        state, lambda m: m.topic == t_delta, deltas_before, hold_s,
        f"a reported write that made every desired leaf agree still published a delta on "
        f"{t_delta!r}; a converged shadow has no delta",
    )

    # ---- Leg 4: THE RECOMPUTE RULE, and the re-proof that the delta path still works at all.
    data.update_thing_shadow(
        thingName=thing,
        payload=json.dumps({"state": {"desired": {"alpha": 9}}}).encode(),
    )
    third = _wait_for_inbox(
        state, lambda m: m.topic == t_delta, deltas_before + 1, 60,
        f"re-diverging one leaf published no delta on {t_delta!r}; leg 3's absence therefore "
        "proves nothing, because this wiring never delivers a delta at all",
    )
    doc3 = json.loads(third[-1].payload)
    assert doc3["state"] == {"alpha": 9}, (
        f"the delta after re-diverging one leaf carried state {doc3['state']!r}, expected "
        "{'alpha': 9}: the delta is RECOMPUTED against the current reported, so beta (which now "
        "agrees) must be absent — an implementation that accumulates deltas emits both leaves"
    )
    v3 = doc3["version"]
    assert v3 > v2, (
        f"the shadow version did not advance past the convergence update: leg 2 saw {v2!r}, "
        f"leg 4 saw {v3!r}"
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


def _delete_shadow(data, thing: str) -> None:
    """Teardown only: a thing with no shadow is the normal case, so a 404 here is success."""
    from botocore.exceptions import ClientError
    try:
        data.delete_thing_shadow(thingName=thing)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
    """A device identity usable for mutual-TLS MQTT: policy + certificate + PEM files on disk.

    The PEM files go in a per-run mkdtemp directory, never a fixed /tmp path — the harness host is
    shared and a predictable name is a cross-run clobber.
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

    cert_path = os.path.join(workdir, f"{label}-cert.pem")
    key_path = os.path.join(workdir, f"{label}-key.pem")
    with open(cert_path, "w") as fh:
        fh.write(cert["certificatePem"])
    with open(key_path, "w") as fh:
        fh.write(cert["keyPair"]["PrivateKey"])
    return {"policy": policy, "cert_id": cert_id, "cert_arn": cert_arn,
            "cert_path": cert_path, "key_path": key_path}


def _mqtt_connect(ctx, host: str, identity: dict, client_id: str, timeout_s: int = 120):
    """A mutually authenticated MQTT 3.1.1 session, with a bounded CONNACK retry.

    The retry is on rc != 0 rather than a bare sleep because the certificate's policy attachment is
    eventually consistent at the broker; a successful CONNACK is therefore also the barrier proving
    the policy is in force.
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
        except OSError as exc:
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


def _assert_count_frozen(state: dict, predicate, expected: int, hold_s: float, what: str) -> None:
    """Hold for *hold_s* and require the match count to stay exactly *expected* throughout.

    Both a calibrated window (hold_s is derived from a latency measured on this same wiring) and a
    freeze detector: the final _FREEZE_READS reads must all agree, so a count that is still moving
    when the window closes fails rather than being sampled once at a lucky instant.
    """
    deadline = time.time() + hold_s
    while time.time() < deadline:
        got = _inbox(state, predicate)
        assert len(got) == expected, (
            f"{what}: the match count moved from {expected!r} to {len(got)!r} during the "
            f"{hold_s:.1f}s hold; newest was {[(m.topic, m.payload) for m in got[expected:]]!r}"
        )
        time.sleep(0.5)
    for _ in range(_FREEZE_READS):
        got = _inbox(state, predicate)
        assert len(got) == expected, (
            f"{what}: the count was {len(got)!r} on a settling read, expected a frozen {expected!r}"
        )
        time.sleep(0.5)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
