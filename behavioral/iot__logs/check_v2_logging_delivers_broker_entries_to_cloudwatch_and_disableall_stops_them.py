"""v2-logging-delivers-broker-entries-to-cloudwatch-and-disableall-stops-them."""
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

CHECK = "v2-logging-delivers-broker-entries-to-cloudwatch-and-disableall-stops-them"
GROUP = "event-propagation"
SERVICES = ["iot", "logs"]

# AWS creates and owns this group; the check reads it and never deletes it.
_LOG_GROUP = "AWSIotLogsV2"
_LOGGING_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSIoTLogging"
_LOG_DELIVERY_DEADLINE_S = 300.0
_MIN_ABSENCE_HOLD_S = 60.0
_FREEZE_READS = 3


@tags(
    "axis:negative-delivery",
    "cap:c1",
    "cap:c6",
    "concern:data-plane",
    "concern:eventing",
    "concern:metrics",
    "dp:native",
    "plane:data", "resource:account-singleton:iot-logging",
)
def run(ctx) -> None:
    """IoT V2 logging really delivers broker entries to CloudWatch Logs, and disableAllLogs stops it.

    An MQTT session's entries (client id, certificate principal, topic) appear in `AWSIotLogsV2`;
    with `disableAllLogs=True` a fresh session logs nothing, and restoring the flag logs again.
    """
    iot = ctx.client("iot")
    iam = ctx.client("iam")
    logs = ctx.client("logs")
    from botocore.exceptions import ClientError

    scenario = "iot-v2-logging-to-cloudwatch"

    # ---- ACCOUNT-GLOBAL SINGLETON: snapshot and restore, because there is no DeleteV2LoggingOptions.
    try:
        previous = iot.get_v2_logging_options()
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotConfiguredException":
            raise
        previous = None

    def _restore_options():
        if previous is not None:
            iot.set_v2_logging_options(
                roleArn=previous["roleArn"],
                defaultLogLevel=previous.get("defaultLogLevel", "WARN"),
                disableAllLogs=previous.get("disableAllLogs", False),
            )
        else:
            # The account had no V2 logging before this check; leave it disabled rather than
            # inventing a configuration it never had.
            iot.set_v2_logging_options(roleArn=role_arn, disableAllLogs=True)

    role_name = ctx.unique_name("sim2real-iot-logrole-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "iot.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Tags=[{"Key": "sim2real", "Value": scenario}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_LOGGING_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(
        RoleName=role_name, PolicyArn=_LOGGING_POLICY_ARN))
    ctx.on_cleanup(_restore_options)

    # SetV2LoggingOptions rejects a role IAM has not finished propagating; bounded retry, not a sleep.
    _retry_client_error(
        lambda: iot.set_v2_logging_options(
            roleArn=role_arn, defaultLogLevel="DEBUG", disableAllLogs=False),
        what="SetV2LoggingOptions never accepted the freshly created logging role",
    )
    options = _poll_until(
        iot.get_v2_logging_options,
        lambda o: o.get("roleArn") == role_arn and o.get("disableAllLogs") is False,
        timeout_s=60.0,
        what="GetV2LoggingOptions never reported the role and disableAllLogs=False this check set",
    )
    assert options["defaultLogLevel"] == "DEBUG", (
        f"GetV2LoggingOptions reported defaultLogLevel {options.get('defaultLogLevel')!r}, "
        "expected 'DEBUG'"
    )

    host = _ats_endpoint(ctx)
    workdir = tempfile.mkdtemp(prefix="sim2real-iot-logging-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))
    identity = _provision_identity(
        ctx, iot, workdir,
        ["iot:Connect", "iot:Publish", "iot:Subscribe", "iot:Receive"],
        scenario, "device",
    )

    # ---- POSITIVE CONTROL at the consumer: logging on, entries must arrive.
    topic = f"sim2real/{ctx.unique_name('lg')}/telemetry"
    client_id = ctx.unique_name("sim2real-iot-logged-")
    started_ms = int(time.time() * 1000) - 60_000
    t0 = time.monotonic()
    _connect_and_publish(ctx, host, identity, client_id, topic)

    entries = _poll_until(
        lambda: _entries_for(logs, client_id, started_ms),
        lambda found: any(e.get("eventType") == "Connect" for e in found)
        and any(e.get("topicName") == topic for e in found),
        timeout_s=_LOG_DELIVERY_DEADLINE_S,
        what=(
            f"no {_LOG_GROUP!r} entries naming client id {client_id!r} carried both a Connect event "
            f"and the published topic {topic!r} within {_LOG_DELIVERY_DEADLINE_S}s"
        ),
        interval_s=5.0,
    )
    log_latency = time.monotonic() - t0

    connects = [e for e in entries if e.get("eventType") == "Connect"]
    assert connects, (
        f"{_LOG_GROUP!r} held {len(entries)!r} entries for {client_id!r} but none with "
        f"eventType 'Connect': {[e.get('eventType') for e in entries]!r}"
    )
    connect_entry = connects[0]
    assert connect_entry["clientId"] == client_id, (
        f"the Connect entry named clientId {connect_entry.get('clientId')!r}, expected "
        f"{client_id!r}"
    )
    assert connect_entry["status"] == "Success", (
        f"the Connect entry for a certificate that really did connect reported status "
        f"{connect_entry.get('status')!r}, expected 'Success'"
    )
    assert connect_entry["principalId"] == identity["cert_id"], (
        f"the Connect entry attributed the session to principalId "
        f"{connect_entry.get('principalId')!r}, expected this check's certificate id "
        f"{identity['cert_id']!r}; an entry that is not attributable to the authenticating "
        "certificate does not prove IoT logged THIS session"
    )

    publishes = [e for e in entries if e.get("topicName") == topic]
    assert publishes, (
        f"{_LOG_GROUP!r} held no entry for {client_id!r} naming the published topic {topic!r}; "
        f"the entries seen were {[(e.get('eventType'), e.get('topicName')) for e in entries]!r}"
    )
    assert publishes[0]["clientId"] == client_id, (
        f"the topic entry named clientId {publishes[0].get('clientId')!r}, expected {client_id!r}"
    )

    # ---- BREAK EXACTLY ONE THING: disableAllLogs. The role, the level and the wiring are untouched.
    iot.set_v2_logging_options(roleArn=role_arn, defaultLogLevel="DEBUG", disableAllLogs=True)
    disabled = _poll_until(
        iot.get_v2_logging_options,
        lambda o: o.get("disableAllLogs") is True,
        timeout_s=60.0,
        what="GetV2LoggingOptions never reported disableAllLogs=True",
    )
    assert disabled["disableAllLogs"] is True, (
        f"GetV2LoggingOptions reported disableAllLogs={disabled.get('disableAllLogs')!r} after it "
        "was set to True"
    )

    silent_id = ctx.unique_name("sim2real-iot-silent-")
    silent_topic = f"sim2real/{ctx.unique_name('lg')}/silent"
    silent_from_ms = int(time.time() * 1000) - 60_000
    _connect_and_publish(ctx, host, identity, silent_id, silent_topic)

    # CALIBRATED WINDOW: 3x the log latency measured above on this exact wiring, floored so a merely
    # slower ingestion path cannot read as having been disabled.
    hold_s = max(_FREEZE_READS * log_latency, _MIN_ABSENCE_HOLD_S)
    deadline = time.time() + hold_s
    while time.time() < deadline:
        leaked = _entries_for(logs, silent_id, silent_from_ms)
        assert leaked == [], (
            f"disableAllLogs=True still delivered {len(leaked)!r} {_LOG_GROUP!r} entries for the "
            f"session {silent_id!r}: {[(e.get('eventType'), e.get('topicName')) for e in leaked]!r}"
        )
        time.sleep(5)
    for _ in range(_FREEZE_READS):
        leaked = _entries_for(logs, silent_id, silent_from_ms)
        assert leaked == [], (
            f"disableAllLogs=True delivered {len(leaked)!r} entries for {silent_id!r} on a settling "
            f"read after a {hold_s:.0f}s hold"
        )
        time.sleep(5)

    # ---- RESTORE, and demand the identical session logs again.
    iot.set_v2_logging_options(roleArn=role_arn, defaultLogLevel="DEBUG", disableAllLogs=False)
    _poll_until(
        iot.get_v2_logging_options,
        lambda o: o.get("disableAllLogs") is False,
        timeout_s=60.0,
        what="GetV2LoggingOptions never reported disableAllLogs back to False",
    )

    restored_id = ctx.unique_name("sim2real-iot-restored-")
    restored_topic = f"sim2real/{ctx.unique_name('lg')}/restored"
    restored_from_ms = int(time.time() * 1000) - 60_000
    _connect_and_publish(ctx, host, identity, restored_id, restored_topic)

    restored_entries = _poll_until(
        lambda: _entries_for(logs, restored_id, restored_from_ms),
        lambda found: any(e.get("eventType") == "Connect" for e in found),
        timeout_s=_LOG_DELIVERY_DEADLINE_S,
        what=(
            f"re-enabling logging did not make the identical session log again: no Connect entry "
            f"for {restored_id!r} appeared in {_LOG_GROUP!r} within {_LOG_DELIVERY_DEADLINE_S}s, so "
            "the absence proven above is not attributable to disableAllLogs"
        ),
        interval_s=5.0,
    )
    restored_connect = [e for e in restored_entries if e.get("eventType") == "Connect"][0]
    assert restored_connect["clientId"] == restored_id, (
        f"the post-restore Connect entry named clientId {restored_connect.get('clientId')!r}, "
        f"expected {restored_id!r}"
    )
    assert restored_connect["principalId"] == identity["cert_id"], (
        f"the post-restore Connect entry attributed the session to "
        f"{restored_connect.get('principalId')!r}, expected {identity['cert_id']!r}"
    )


def _entries_for(logs, client_id: str, start_ms: int) -> list[dict]:
    """Every JSON-decodable AWSIotLogsV2 entry mentioning *client_id* since *start_ms*.

    A missing log group means AWS has not created it yet, which is indistinguishable from "no entries
    yet" for this check's purposes; the CALLER always wraps this in a bounded poll that raises, so
    returning an empty list here can never turn a timeout into a pass. The empty-list default is
    also the correct polarity for the absence leg, which asserts `== []`.
    """
    from botocore.exceptions import ClientError
    found: list[dict] = []
    token = None
    while True:
        kwargs = {
            "logGroupName": _LOG_GROUP,
            "startTime": start_ms,
            "filterPattern": f'"{client_id}"',
            "limit": 1000,
        }
        if token:
            kwargs["nextToken"] = token
        try:
            page = logs.filter_log_events(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return []
            raise
        for event in page.get("events", []):
            try:
                entry = json.loads(event["message"])
            except ValueError:
                continue  # IoT emits JSON entries; a non-JSON line is not one of ours
            if entry.get("clientId") == client_id:
                found.append(entry)
        token = page.get("nextToken")
        if not token:
            return found


def _poll_until(probe, predicate, *, timeout_s: float, what: str, interval_s: float = 3.0):
    """Bounded retry with a stated reason; RAISES on timeout rather than returning its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what}; last observation was {last!r} after {timeout_s}s")


def _retry_client_error(fn, *, what: str, attempts: int = 10, interval_s: float = 5.0):
    """Bounded retry over IAM propagation; RAISES the last error rather than swallowing it."""
    from botocore.exceptions import ClientError
    last = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as err:
            last = err
            time.sleep(interval_s)
    raise AssertionError(f"{what}: {last!r}")


def _ats_endpoint(ctx) -> str:
    """The account's own iot:Data-ATS broker host, once its DNS record exists."""
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


def _connect_and_publish(ctx, host: str, identity: dict, client_id: str, topic: str) -> None:
    """One full MQTT session: connect, publish once at qos 1, disconnect. Raises on any failure."""
    client, state = _mqtt_connect(ctx, host, identity, client_id)
    assert state["rc"] == 0, (
        f"{client_id!r} did not reach CONNACK rc=0 (rc={state['rc']!r}); nothing can be expected in "
        "the log group for a session that never happened"
    )
    payload = json.dumps({"marker": ctx.unique_name("log-"), "topic": topic}).encode()
    info = client.publish(topic, payload, qos=1)
    deadline = time.time() + 30
    while time.time() < deadline and not info.is_published():
        time.sleep(0.1)
    assert info.is_published(), (
        f"the broker never PUBACKed {client_id!r}'s publish to {topic!r}, so no publish log entry "
        "can be expected"
    )
    _mqtt_close(client)


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
