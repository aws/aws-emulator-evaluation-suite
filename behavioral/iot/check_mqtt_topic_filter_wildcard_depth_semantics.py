"""mqtt-topic-filter-wildcard-depth-semantics."""
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

CHECK = "mqtt-topic-filter-wildcard-depth-semantics"
GROUP = "mqtt-data-plane"
SERVICES = ["iot"]

# The exclusion legs hold for at least this long even if the measured delivery latency is tiny, so a
# broker that is merely slower than this run's positive control cannot read as having filtered.
_MIN_ABSENCE_HOLD_S = 15.0
_FREEZE_READS = 3


@tags(
    "axis:negative-delivery",
    "cap:c6",
    "concern:data-plane",
    "concern:eventing",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """`+` matches exactly one topic level and `#` matches one or more, on the real broker.

    Filters `<base>/+`, `<base>/#`, `<base>/+/+` and `<base>` each receive exactly the publishes at
    depths 1-3 they match, so `+` and `#` are not the same prefix match.
    """
    iot = ctx.client("iot")
    host = _ats_endpoint(ctx)

    workdir = tempfile.mkdtemp(prefix="sim2real-iot-wildcard-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))

    identity = _provision_identity(
        ctx, iot, workdir,
        ["iot:Connect", "iot:Publish", "iot:Subscribe", "iot:Receive"],
        "mqtt-wildcard-depth", "device",
    )

    base = ctx.unique_name("sim2realwc")
    depth1 = base
    depth2 = f"{base}/one"
    depth3 = f"{base}/one/two"

    # filter -> (label, the exact set of published topics it must receive)
    plan = {
        f"{base}/+": ("plus", {depth2}),
        f"{base}/#": ("hash", {depth2, depth3}),
        f"{base}/+/+": ("plusplus", {depth3}),
        base: ("exact", {depth1}),
    }

    subs: dict[str, dict] = {}
    for filt, (label, _expected) in plan.items():
        client, state = _mqtt_connect(
            ctx, host, identity, ctx.unique_name(f"sim2real-iot-wc-{label}-"))
        assert state["rc"] == 0, (
            f"the {label!r} subscriber's CONNACK was rc={state['rc']!r}, expected 0"
        )
        granted = _subscribe(client, state, filt, qos=1)
        assert granted == [1], (
            f"SUBACK for the filter {filt!r} granted {granted!r}, expected [1]; 128 means the "
            "broker refused the subscription and every absence below would be unattributable"
        )
        subs[filt] = {"label": label, "client": client, "state": state}

    publisher, pub_state = _mqtt_connect(
        ctx, host, identity, ctx.unique_name("sim2real-iot-wc-pub-"))
    assert pub_state["rc"] == 0, (
        f"the publisher's CONNACK was rc={pub_state['rc']!r}, expected 0"
    )

    payloads = {}
    t0 = time.monotonic()
    for topic in (depth1, depth2, depth3):
        payload = json.dumps({"topic": topic, "marker": ctx.unique_name("p-")}).encode()
        payloads[topic] = payload
        info = publisher.publish(topic, payload, qos=1)
        deadline = time.time() + 30
        while time.time() < deadline and not info.is_published():
            time.sleep(0.1)
        assert info.is_published(), (
            f"the broker never PUBACKed the qos-1 publish to {topic!r}; nothing downstream of this "
            "publish can be graded"
        )

    # POSITIVE CONTROL, one per subscription: wait for every EXPECTED arrival first. A subscription
    # with no expected arrivals would make its own emptiness meaningless, so the plan gives all four
    # at least one, including the exact-topic subscriber whose only job is to prove that `<base>`
    # itself really reached the broker.
    for filt, spec in subs.items():
        expected = plan[filt][1]
        _wait_for_inbox(
            spec["state"], lambda m, e=expected: m.topic in e, len(expected), 90,
            f"the filter {filt!r} did not receive its {len(expected)} matching publish(es); its "
            "own exclusions below would then prove nothing",
        )
    delivery_latency = time.monotonic() - t0

    # CALIBRATED WINDOW: hold for 3x the delivery latency measured on this exact wiring in this run,
    # then require each inbox's topic set to be EXACTLY the filter's match set.
    hold_s = max(_FREEZE_READS * delivery_latency, _MIN_ABSENCE_HOLD_S)
    _hold(hold_s)

    observed = {}
    for filt, spec in subs.items():
        got = {m.topic for m in _inbox(spec["state"], lambda m: True)}
        observed[filt] = got

    for filt, spec in subs.items():
        expected = plan[filt][1]
        assert observed[filt] == expected, (
            f"the filter {filt!r} received the topic set {sorted(observed[filt])!r}, expected "
            f"exactly {sorted(expected)!r} after a {hold_s:.1f}s hold"
        )

    # The same facts again as separately named claims, so a failure report names the specific
    # wildcard rule that broke rather than only a set difference.
    assert depth3 not in observed[f"{base}/+"], (
        f"the single-level filter {base + '/+'!r} received the depth-3 topic {depth3!r}; `+` "
        "matches EXACTLY one level and must not span a further slash"
    )
    assert depth3 in observed[f"{base}/#"], (
        f"the multi-level filter {base + '/#'!r} did not receive the depth-3 topic {depth3!r}; `#` "
        f"matches all levels at and below its position, and it received {sorted(observed[base + '/#'])!r}"
    )
    assert depth2 not in observed[f"{base}/+/+"], (
        f"the filter {base + '/+/+'!r} received the depth-2 topic {depth2!r}; two `+` levels "
        "require exactly two further levels, and depth2 has only one"
    )
    # The AWS-documented divergence from MQTT 3.1.1: `<base>/#` does not match `<base>` itself.
    # Kept as its own assertion, separate from the legs above.
    assert depth1 not in observed[f"{base}/#"], (
        f"the filter {base + '/#'!r} received the bare parent topic {depth1!r}; AWS IoT documents "
        "that `sensor/#` does NOT match `sensor` (topics.html), which diverges from MQTT 3.1.1 "
        "4.7.1.2 — and the exact-topic subscriber proved this publish did reach the broker"
    )
    assert depth1 in observed[base], (
        f"the exact-topic subscriber on {base!r} did not receive {depth1!r}, so the claim above "
        f"about `#` is unattributable; it received {sorted(observed[base])!r}"
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
    """A calibrated absence window, not an unconditional wait.

    *seconds* is always derived from a delivery latency measured on this same wiring earlier in this
    same run (floored at _MIN_ABSENCE_HOLD_S), which is what makes a subsequent emptiness evidence
    of filtering rather than of a slower-but-correct broker.
    """
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
