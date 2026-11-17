"""iot-job-document-is-delivered-over-mqtt-and-the-device-reported-completion-is-recorded."""
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

CHECK = "iot-job-document-is-delivered-over-mqtt-and-the-device-reported-completion-is-recorded"
GROUP = 'mqtt-data-plane'
SERVICES = ['iot']


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


def _delete_job(iot, job_id: str) -> None:
    """force=True is required: a job with live executions refuses deletion, and a thing with a
    surviving job execution refuses deletion too, so the thing's own cleanup would fail after
    this one. Deletion is asynchronous, so wait it out."""
    iot.delete_job(jobId=job_id, force=True)
    deadline = time.time() + 120
    while time.time() < deadline:
        try:
            iot.describe_job(jobId=job_id)
        except iot.exceptions.ResourceNotFoundException:
            return
        time.sleep(3)
    raise RuntimeError(
        f"job {job_id!r} was still describable 120s after delete_job(force=True)"
    )


def _provision_identity(ctx, iot, workdir: str, actions: list[str], scenario: str, label: str):
    """A device identity usable for mutual-TLS MQTT: thing + policy + certificate + PEM files.

    The PEM files go in a per-run mkdtemp directory, never a fixed /tmp path -- the harness host
    is shared, and a predictable name is a measured cross-run clobber.
    """
    thing = ctx.unique_name("sim2real-iot-thing-")
    thing_arn = iot.create_thing(
        thingName=thing, attributePayload={"attributes": {"sim2real": scenario}})["thingArn"]
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
    return {"thing": thing, "thing_arn": thing_arn, "policy": policy, "cert_id": cert_id,
            "cert_arn": cert_arn, "cert_path": cert_path, "key_path": key_path}


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


def _wait_for_topic(state: dict, topic: str, timeout_s: int, what: str):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        with state["lock"]:
            hits = [m for m in state["messages"] if m.topic == topic]
        if hits:
            return hits[0]
        time.sleep(0.2)
    with state["lock"]:
        seen = [(m.topic, m.payload[:200]) for m in state["messages"]]
    raise AssertionError(f"{what} within {timeout_s}s; the inbox held {seen!r}")


def _eventually(fn, predicate, timeout_s: int, what: str):
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        last = fn()
        if predicate(last):
            return last
        time.sleep(3)
    raise AssertionError(f"{what} within {timeout_s}s; last read was {last!r}")


@tags("axis:happy-path", "concern:data-plane", "dp:native", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A job crosses the data plane twice: the jobs service pushes the document CreateJob supplied
    to a subscribed device over MQTT, and the device's MQTT status report advances the service's
    own execution record and aggregation counters."""
    iot = ctx.client("iot")
    host = _ats_endpoint(ctx)

    workdir = tempfile.mkdtemp(prefix="sim2real-iot-mqtt-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))

    identity = _provision_identity(
        ctx, iot, workdir,
        ["iot:Connect", "iot:Publish", "iot:Subscribe", "iot:Receive"],
        "mqtt-job-roundtrip", "device",
    )
    thing = identity["thing"]
    job_id = ctx.unique_name("sim2real-iot-job-")

    notify_next = f"$aws/things/{thing}/jobs/notify-next"
    update_topic = f"$aws/things/{thing}/jobs/{job_id}/update"
    accepted_topic = f"{update_topic}/accepted"
    rejected_topic = f"{update_topic}/rejected"

    device, dev_state = _mqtt_connect(ctx, host, identity, ctx.unique_name("sim2real-iot-dev-"))
    assert dev_state["rc"] == 0, f"the device's CONNACK was {dev_state['rc']!r}"
    # A reserved-topic subscription that the policy does not cover comes back as a granted QoS of
    # 128 and then simply never delivers, which would look like a broken jobs service. Assert the
    # SUBACK first so a policy error fails here instead of timing out ambiguously later.
    for topic in (notify_next, accepted_topic, rejected_topic):
        granted = _subscribe(device, dev_state, topic, qos=1)
        assert granted == [1], f"SUBACK for the reserved topic {topic!r} granted {granted!r}"

    marker = ctx.unique_name("jobdoc-")
    iot.create_job(
        jobId=job_id,
        targets=[identity["thing_arn"]],
        document=json.dumps({"marker": marker, "operation": "sim2real-noop"}),
        targetSelection="SNAPSHOT",
        description="sim2real behavioral job round trip",
        tags=[{"Key": "sim2real", "Value": "mqtt-job-roundtrip"}],
    )
    ctx.on_cleanup(lambda: _delete_job(iot, job_id))

    notify = _wait_for_topic(
        dev_state, notify_next, 120,
        f"the jobs service never pushed a document on {notify_next!r}",
    )
    execution = json.loads(notify.payload)["execution"]
    assert execution["jobId"] == job_id, f"notify-next announced job {execution['jobId']!r}"
    assert execution["jobDocument"]["marker"] == marker, (
        f"the delivered job document was {execution['jobDocument']!r}, expected marker {marker!r}"
    )
    assert execution["jobDocument"]["operation"] == "sim2real-noop", (
        f"the delivered job document was {execution['jobDocument']!r}"
    )
    assert execution["status"] == "QUEUED", (
        f"a freshly created SNAPSHOT execution was announced as {execution['status']!r}"
    )

    detail = ctx.unique_name("done-")
    # includeJobExecutionState is load-bearing, measured: without it the update/accepted payload
    # is only {"clientToken", "timestamp"} and carries nothing to assert against.
    device.publish(update_topic, json.dumps({
        "status": "SUCCEEDED",
        "statusDetails": {"sim2real": detail},
        "includeJobExecutionState": True,
    }).encode(), qos=1)
    with dev_state["lock"]:
        rejected = [m for m in dev_state["messages"] if m.topic == rejected_topic]
    assert rejected == [], f"the jobs service rejected the status report: {rejected!r}"
    accepted = _wait_for_topic(
        dev_state, accepted_topic, 120,
        f"the jobs service never accepted the device status report on {accepted_topic!r}",
    )
    # Measured: the accepted payload carries the new state under "executionState", not a
    # top-level "status" -- the plan's shape was wrong and real AWS wins.
    accepted_state = json.loads(accepted.payload)["executionState"]
    assert accepted_state["status"] == "SUCCEEDED", (
        f"the acceptance echoed execution state {accepted_state!r}"
    )
    assert accepted_state["statusDetails"] == {"sim2real": detail}, (
        f"the acceptance did not echo the device's statusDetails: {accepted_state!r}"
    )

    got = _eventually(
        lambda: iot.describe_job_execution(jobId=job_id, thingName=thing)["execution"],
        lambda e: e["status"] == "SUCCEEDED",
        120, "DescribeJobExecution never reported the MQTT-reported SUCCEEDED",
    )
    assert got["statusDetails"]["detailsMap"]["sim2real"] == detail, (
        f"the device's statusDetails did not survive the round trip: {got['statusDetails']!r}"
    )

    job = _eventually(
        lambda: iot.describe_job(jobId=job_id)["job"],
        lambda j: j["status"] == "COMPLETED",
        180, "the job never aggregated to COMPLETED after its only target succeeded",
    )
    assert job["jobProcessDetails"]["numberOfSucceededThings"] == 1, (
        f"the job's aggregation counters are {job['jobProcessDetails']!r}"
    )
    assert job["jobProcessDetails"]["numberOfFailedThings"] == 0, (
        f"the job counted a failure: {job['jobProcessDetails']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
