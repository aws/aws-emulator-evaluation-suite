"""get-thing-connectivity-data-reflects-mqtt-state."""
from __future__ import annotations

import json
import os
import ssl
import tempfile
import time

from behavioral_harness import tags

CHECK = "get-thing-connectivity-data-reflects-mqtt-state"
GROUP = "server-side"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c4", "cap:c6", "concern:data-plane", "dp:native", "plane:data", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """GetThingConnectivityData reports a thing as connected only while its MQTT
    connection is actually open on IoT Core's native MQTT broker, flipping to
    disconnected shortly after the client disconnects."""
    import paho.mqtt.client as mqtt

    iot = ctx.client("iot")

    # --- Enable connectivity indexing, preserving+restoring the account's prior config ---
    idx_before = iot.get_indexing_configuration()
    orig_thing_cfg = idx_before.get("thingIndexingConfiguration", {"thingIndexingMode": "OFF"})
    orig_group_cfg = idx_before.get("thingGroupIndexingConfiguration", {"thingGroupIndexingMode": "OFF"})

    new_thing_cfg = dict(orig_thing_cfg)
    if new_thing_cfg.get("thingIndexingMode", "OFF") == "OFF":
        new_thing_cfg["thingIndexingMode"] = "REGISTRY"
    new_thing_cfg["thingConnectivityIndexingMode"] = "STATUS"
    iot.update_indexing_configuration(
        thingIndexingConfiguration=new_thing_cfg, thingGroupIndexingConfiguration=orig_group_cfg
    )
    ctx.on_cleanup(
        lambda: iot.update_indexing_configuration(
            thingIndexingConfiguration=orig_thing_cfg, thingGroupIndexingConfiguration=orig_group_cfg
        )
    )

    # --- Provision a thing + certificate + connect-only policy ---
    thing_name = ctx.unique_name("sim2real-iot-conn-")
    iot.create_thing(thingName=thing_name)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    cert = iot.create_keys_and_certificate(setAsActive=True)
    cert_arn = cert["certificateArn"]
    cert_id = cert["certificateId"]
    cert_pem = cert["certificatePem"]
    private_key = cert["keyPair"]["PrivateKey"]

    policy_name = ctx.unique_name("sim2real-iot-connpolicy-")
    iot.create_policy(
        policyName=policy_name,
        policyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "iot:Connect", "Resource": "*"}],
            }
        ),
        tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iot.delete_policy(policyName=policy_name))

    iot.attach_policy(policyName=policy_name, target=cert_arn)
    iot.attach_thing_principal(thingName=thing_name, principal=cert_arn)

    def _cleanup_cert():
        iot.detach_thing_principal(thingName=thing_name, principal=cert_arn)
        iot.detach_policy(policyName=policy_name, target=cert_arn)
        iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
        iot.delete_certificate(certificateId=cert_id)

    ctx.on_cleanup(_cleanup_cert)

    endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]

    cert_file = tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False)
    cert_file.write(cert_pem)
    cert_file.close()
    key_file = tempfile.NamedTemporaryFile(mode="w", suffix=".key", delete=False)
    key_file.write(private_key)
    key_file.close()
    ctx.on_cleanup(lambda: os.unlink(cert_file.name))
    ctx.on_cleanup(lambda: os.unlink(key_file.name))

    connect_state = {"rc": None}

    def _on_connect(client, userdata, flags, rc, *_args):
        connect_state["rc"] = rc

    client = mqtt.Client(client_id=thing_name, protocol=mqtt.MQTTv311)
    client.tls_set(cert_reqs=ssl.CERT_NONE, certfile=cert_file.name, keyfile=key_file.name, tls_version=ssl.PROTOCOL_TLS_CLIENT)
    client.on_connect = _on_connect
    try:
        client.connect(*ctx.endpoint_host(endpoint, 8883), keepalive=30)
    except OSError as exc:
        raise AssertionError(f"MQTT connect to endpoint {endpoint!r}:8883 failed: {exc}") from exc
    client.loop_start()
    ctx.on_cleanup(client.loop_stop)

    _poll_until(lambda: connect_state["rc"], lambda rc: rc is not None, timeout_s=20.0, interval_s=0.5)
    assert connect_state["rc"] == 0, f"MQTT connect failed with rc={connect_state['rc']}"

    try:
        connected = _poll_until(
            lambda: _get_connectivity(iot, thing_name),
            lambda data: data is not None and data["connected"] is True,
            timeout_s=90.0,
            interval_s=3.0,
        )
        assert connected["connected"] is True, f"expected connected=True, got {connected['connected']!r}"
        assert connected["thingName"] == thing_name, (
            f"expected thingName={thing_name!r}, got {connected['thingName']!r}"
        )
    finally:
        client.disconnect()
        client.loop_stop()

    disconnected = _poll_until(
        lambda: _get_connectivity(iot, thing_name),
        lambda data: data is not None and data["connected"] is False,
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert disconnected["connected"] is False, (
        f"expected connected=False after MQTT disconnect, got {disconnected['connected']!r}"
    )


def _get_connectivity(iot, thing_name):
    try:
        return iot.get_thing_connectivity_data(thingName=thing_name)
    except iot.exceptions.IndexNotReadyException:
        return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
