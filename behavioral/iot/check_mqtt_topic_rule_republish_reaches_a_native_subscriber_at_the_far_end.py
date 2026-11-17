"""mqtt-topic-rule-republish-reaches-a-native-subscriber-at-the-far-end."""
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

CHECK = "mqtt-topic-rule-republish-reaches-a-native-subscriber-at-the-far-end"
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


def _iot_publish_role(ctx, dest_topic_arn: str, scenario: str) -> str:
    """An IAM role AWS IoT can assume to republish, with a bounded assumability wait.

    The wait is not decoration: CreateTopicRule validates that the service can assume the role, and
    a freshly created role is not yet assumable, so the create fails until IAM has propagated.
    There is no API that reports propagation, which is the one sanctioned place for a short sleep --
    and it is paired with the bounded retry in the caller, which is what makes it correct.
    """
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-iot-rule-role-")
    iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Description=f"sim2real {scenario}",
        Tags=[{"Key": "sim2real", "Value": scenario}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role))
    iam.put_role_policy(
        RoleName=role, PolicyName="republish",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iot:Publish",
                           "Resource": dest_topic_arn}],
        }),
    )
    return iam.get_role(RoleName=role)["Role"]["Arn"]


def _delete_role(iam, role: str) -> None:
    for name in iam.list_role_policies(RoleName=role).get("PolicyNames", []):
        try:
            iam.delete_role_policy(RoleName=role, PolicyName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
    iam.delete_role(RoleName=role)


# ===== the check =====

@tags("axis:happy-path", "cap:c3", "cap:c6", "concern:data-plane", "concern:eventing",
      "dp:native", "plane:data")
def run(ctx) -> None:
    """A message PUBLISHed over MQTT to a rule's source topic is re-emitted by the rules engine to
    its destination topic, where a second native MQTT subscriber receives it carrying the field the
    rule's SQL computed -- proving ingress, SQL evaluation and egress, asserted at the far end."""
    iot = ctx.client("iot")
    account = ctx.client("sts").get_caller_identity()["Account"]
    host = _ats_endpoint(ctx)

    workdir = tempfile.mkdtemp(prefix="sim2real-iot-mqtt-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))

    scenario = "mqtt-rule-republish-far-end"
    base = f"sim2real/{ctx.unique_name('m')}"
    source = f"{base}/src"
    dest = f"{base}/dst"
    dest_arn = f"arn:aws:iot:{ctx.region}:{account}:topic/{dest}"

    identity = _provision_identity(
        ctx, iot, workdir,
        [{"Effect": "Allow",
          "Action": ["iot:Connect", "iot:Publish", "iot:Subscribe", "iot:Receive"],
          "Resource": "*"}],
        scenario, "device",
    )
    role_arn = _iot_publish_role(ctx, dest_arn, scenario)

    # A topic rule name is alphanumeric-and-underscore only, so the hyphenated unique name has to
    # be transliterated -- a literal name would collide with a concurrent sibling run.
    rule = ctx.unique_name("sim2real_iot_rule_").replace("-", "_")
    payload = {
        "sql": f"SELECT *, topic() AS src FROM '{source}'",
        "awsIotSqlVersion": "2016-03-23",
        "description": f"sim2real {scenario}",
        "actions": [{"republish": {"roleArn": role_arn, "topic": dest, "qos": 1}}],
    }
    # Bounded retry on role assumability: CreateTopicRule validates the role and fails until IAM
    # has propagated it. The loop is what makes this correct; it is not a throttle retry.
    deadline = time.time() + 180
    last = None
    created = False
    while time.time() < deadline:
        try:
            iot.create_topic_rule(ruleName=rule, topicRulePayload=payload,
                                  tags=f"sim2real={scenario}")
            created = True
            break
        except Exception as exc:  # noqa: BLE001 - reported below if it never clears
            last = exc
            time.sleep(5)
    assert created, f"CreateTopicRule({rule!r}) never succeeded within 180s; last error {last!r}"
    ctx.on_cleanup(lambda: iot.delete_topic_rule(ruleName=rule))

    subscriber, sub_state = _mqtt_connect(
        ctx, host, identity, ctx.unique_name("sim2real-iot-farend-"))
    assert sub_state["rc"] == 0, f"the far-end subscriber's CONNACK was {sub_state['rc']!r}"
    # Subscribe ONLY to the destination. A wildcard over the base would also catch the original
    # publish on the source topic, and an inbox holding both proves nothing about the rule.
    granted = _subscribe(subscriber, sub_state, dest, qos=1)
    assert granted == [1], f"the far-end SUBACK on {dest!r} granted {granted!r}, expected [1]"

    publisher, pub_state = _mqtt_connect(
        ctx, host, identity, ctx.unique_name("sim2real-iot-pub-"))
    assert pub_state["rc"] == 0, f"the publisher's CONNACK was {pub_state['rc']!r}, expected 0"

    marker = ctx.unique_name("routed-")
    # The rule becomes effective asynchronously, so the source publish is REPEATED on a bounded
    # deadline until the far end sees something. Re-publishing an identical payload is safe: the
    # assertion is on content, and the rules engine is not being graded for exactly-once.
    deadline = time.time() + 180
    arrived = None
    while time.time() < deadline and arrived is None:
        _publish_acked(publisher, source, json.dumps({"marker": marker}).encode())
        settle = time.time() + 15
        while time.time() < settle and arrived is None:
            for raw in _payloads(sub_state, dest):
                body = json.loads(raw)
                if body.get("marker") == marker:
                    arrived = body
                    break
            time.sleep(0.5)
    assert arrived is not None, (
        f"a publish to the rule's source topic {source!r} never produced a republished message on "
        f"{dest!r} within 180s; the far-end inbox held {_payloads(sub_state, dest)!r}"
    )
    # The SQL ran: `topic()` is computed by the rules engine and cannot be in what was published.
    assert arrived.get("src") == source, (
        f"the republished message's rule-computed src was {arrived.get('src')!r}, expected "
        f"{source!r}; the whole message was {arrived!r}"
    )
    assert arrived["marker"] == marker, (
        f"the republished message carried marker {arrived['marker']!r}, published {marker!r}"
    )
    # `SELECT *` must not smuggle the destination topic into the body, and the original publish
    # must not have reached the far-end subscriber directly -- only the rule's output did.
    assert set(arrived) == {"marker", "src"}, (
        f"the republished body was {arrived!r}; SELECT *, topic() AS src should yield exactly the "
        f"published keys plus src"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
