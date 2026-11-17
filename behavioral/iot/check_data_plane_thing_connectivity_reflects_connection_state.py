"""data-plane-thing-connectivity-reflects-connection-state."""
from __future__ import annotations

import json
import ssl
import tempfile
import time
from pathlib import Path

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "data-plane-thing-connectivity-reflects-connection-state"
GROUP = "server-side"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "cap:c6", "concern:data-plane", "dp:native", "plane:data", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """GetThingConnectivityData tracks a real MQTT session opened over IoT's native protocol:
    'connected' flips to true once the device connects, and back to false once it
    disconnects -- this is the native-protocol data plane, not just control-plane metadata."""
    import paho.mqtt.client as mqtt

    iot = ctx.client("iot")

    original = iot.get_indexing_configuration()
    original_thing_cfg = original.get("thingIndexingConfiguration", {"thingIndexingMode": "OFF"})
    ctx.on_cleanup(lambda: iot.update_indexing_configuration(thingIndexingConfiguration=original_thing_cfg))
    iot.update_indexing_configuration(
        thingIndexingConfiguration={
            "thingIndexingMode": "REGISTRY",
            "thingConnectivityIndexingMode": "STATUS",
        }
    )

    thing_name = ctx.unique_name("sim2real-iot-conn-thing-")
    iot.create_thing(thingName=thing_name)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    cert = iot.create_keys_and_certificate(setAsActive=True)
    cert_arn = cert["certificateArn"]
    cert_id = cert["certificateId"]
    ctx.on_cleanup(lambda: _deactivate_and_delete_cert(iot, cert_id))

    policy_name = ctx.unique_name("sim2real-iot-conn-policy-")
    iot.create_policy(
        policyName=policy_name,
        policyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iot:Connect", "Resource": "*"}]}
        ),
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iot.delete_policy(policyName=policy_name))
    iot.attach_policy(policyName=policy_name, target=cert_arn)
    ctx.on_cleanup(lambda: iot.detach_policy(policyName=policy_name, target=cert_arn))
    iot.attach_thing_principal(thingName=thing_name, principal=cert_arn)
    ctx.on_cleanup(lambda: iot.detach_thing_principal(thingName=thing_name, principal=cert_arn))

    endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]

    with tempfile.TemporaryDirectory() as tmp:
        cert_path = Path(tmp) / "cert.pem"
        key_path = Path(tmp) / "key.pem"
        cert_path.write_text(cert["certificatePem"])
        key_path.write_text(cert["keyPair"]["PrivateKey"])

        connect_state = {"rc": None}

        def _on_connect(client, userdata, flags, rc, *_args):
            connect_state["rc"] = rc

        client = mqtt.Client(client_id=thing_name)
        client.tls_set(
            certfile=str(cert_path),
            keyfile=str(key_path),
            cert_reqs=ssl.CERT_NONE,
            tls_version=ssl.PROTOCOL_TLS_CLIENT,
        )
        client.tls_insecure_set(True)
        client.on_connect = _on_connect
        client.connect(*ctx.endpoint_host(endpoint, 8883), keepalive=30)
        client.loop_start()
        try:
            _poll_until(
                lambda: connect_state["rc"],
                lambda rc: rc is not None,
                timeout_s=20.0,
                interval_s=0.5,
            )
            assert connect_state["rc"] == 0, f"expected a successful MQTT CONNACK (rc=0), got rc={connect_state['rc']}"

            # A freshly enabled connectivity index answers IndexNotReadyException while it builds.
            left = ctx.time_left()
            connected_data = _poll_until(
                lambda: _connectivity_probe(iot, thing_name),
                lambda d: d.get("connected") is True,
                timeout_s=300.0 if left is None else min(300.0, left),
                interval_s=5.0,
            )
            assert connected_data["connected"] is True, f"expected connected=True after MQTT connect, got {connected_data!r}"
            assert connected_data["thingName"] == thing_name, (
                f"expected connectivity data for {thing_name!r}, got thingName={connected_data.get('thingName')!r}"
            )
        finally:
            client.loop_stop()
            client.disconnect()

        disconnected_data = _poll_until(
            lambda: _connectivity_probe(iot, thing_name),
            lambda d: d.get("connected") is False,
            timeout_s=120.0,
            interval_s=5.0,
        )
        assert disconnected_data["connected"] is False, (
            f"expected connected=False after MQTT disconnect, got {disconnected_data!r}"
        )


def _connectivity_probe(iot, thing_name: str) -> dict:
    try:
        return iot.get_thing_connectivity_data(thingName=thing_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("ResourceNotFoundException", "IndexNotReadyException"):
            return {"connected": None}
        raise


def _deactivate_and_delete_cert(iot, cert_id: str) -> None:
    iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    iot.delete_certificate(certificateId=cert_id)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
