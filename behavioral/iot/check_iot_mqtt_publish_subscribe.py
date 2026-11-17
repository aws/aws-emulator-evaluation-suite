"""iot-mqtt-publish-subscribe."""
from __future__ import annotations

import json
import os
import socket
import tempfile
import time


from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "iot-mqtt-publish-subscribe"
GROUP = 'data-plane'
SERVICES = ['iot']

# Prefix of a native data-plane failure. The iot:Data-ATS broker is a public endpoint
# that DescribeEndpoint returns, so an unreachable broker is a failure on every target.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _dp_fail(msg: str) -> None:
    """Raise a native data-plane failure."""
    raise AssertionError(f"{DATAPLANE_MARKER}: {msg}")


def _delete_certificate(iot, cert_id):
    """Teardown: detach policies/things, deactivate, then force-delete; a missing certificate is clean."""
    try:
        cert_arn = iot.describe_certificate(certificateId=cert_id)[
            "certificateDescription"
        ]["certificateArn"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        cert_arn = None
    if cert_arn:
        try:
            for p in iot.list_attached_policies(target=cert_arn).get("policies", []):
                iot.detach_policy(policyName=p["policyName"], target=cert_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            for t in iot.list_principal_things(principal=cert_arn).get("things", []):
                try:
                    iot.detach_thing_principal(thingName=t, principal=cert_arn)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    try:
        iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_certificate(certificateId=cert_id, forceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

def _delete_policy(iot, name):
    """Best-effort teardown: delete non-default versions, detach targets, then delete a policy."""
    try:
        for v in iot.list_policy_versions(policyName=name).get("policyVersions", []):
            if not v.get("isDefaultVersion"):
                try:
                    iot.delete_policy_version(policyName=name, policyVersionId=v["versionId"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        for t in iot.list_targets_for_policy(policyName=name).get("targets", []):
            iot.detach_policy(policyName=name, target=t)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_policy(policyName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

def _wait_for_dns(host, port, timeout_s=180):
    """A freshly minted iot:Data-ATS hostname stays unresolvable for up to a minute."""
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        try:
            socket.getaddrinfo(host, port)
            return
        except OSError as exc:
            last = exc
            time.sleep(3)
    raise AssertionError(f"the ATS endpoint {host!r} never resolved in DNS: {last!r}")


def _mqtt_paho(ctx, endpoint_host, cert_path, key_path, topic, payload, client_id) -> bool:
    import ssl

    import paho.mqtt.client as mqtt  # type: ignore

    import threading
    state = {"ok": False, "rc": None, "connected": threading.Event(), "subscribed": threading.Event()}

    def on_message(_client, _userdata, msg):
        if msg.payload == payload:
            state["ok"] = True

    def on_connect(_client, _userdata, _flags, rc, *_):
        state["rc"] = int(rc)
        if int(rc) == 0:
            state["connected"].set()

    def on_subscribe(_client, _userdata, _mid, *_):
        state["subscribed"].set()

    # paho 2.x requires an explicit callback API version; 1.x does not.
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=client_id)
    except (AttributeError, TypeError):
        client = mqtt.Client(client_id=client_id)

    # cert_reqs=CERT_NONE: encrypted mutual TLS without verifying the server's identity.
    client.tls_set(cert_reqs=ssl.CERT_NONE, certfile=cert_path, keyfile=key_path, tls_version=ssl.PROTOCOL_TLS_CLIENT)
    client.on_message = on_message
    client.on_connect = on_connect
    client.on_subscribe = on_subscribe

    # The certificate's policy attachment is eventually consistent at the broker's
    # authorization cache; retry CONNACK on a bounded deadline instead of sleeping a fixed
    # amount before the first attempt, since the real settle time varies.
    host, port = ctx.endpoint_host(endpoint_host, 8883)
    _wait_for_dns(host, port)
    connect_deadline = time.time() + 60
    while True:
        client.connect(host, port, keepalive=30)
        client.loop_start()
        if state["connected"].wait(timeout=15):
            break
        client.loop_stop()
        last_rc = state["rc"]
        state["connected"].clear()
        if time.time() >= connect_deadline:
            raise AssertionError(
                f"MQTT never connected to {host}:{port} within 60s (last rc={last_rc!r})"
            )
        time.sleep(3)

    try:
        # Wait for SUBACK before publishing: without this barrier, publish races the
        # subscription and IoT drops the message.
        client.subscribe(topic, qos=1)
        assert state["subscribed"].wait(timeout=15), "MQTT never subscribed"
        client.publish(topic, payload, qos=1)
        deadline = time.time() + 30
        while time.time() < deadline and not state["ok"]:
            time.sleep(0.2)
    finally:
        client.loop_stop()
        try:
            client.disconnect()
        except Exception:
            pass
    return state["ok"]

def _mqtt_awsiotsdk(ctx, endpoint_host, cert_path, key_path, topic, payload, client_id) -> bool:
    from awscrt import io as _io  # type: ignore
    from awscrt import mqtt as _mqtt  # type: ignore
    from awsiot import mqtt_connection_builder  # type: ignore

    received = {"ok": False}
    sent = payload

    def on_message(topic, payload, **kwargs):  # awscrt passes every argument by keyword
        if payload == sent:
            received["ok"] = True

    # The SDK's own default port: 443 where ALPN is available (the SDK then offers ALPN
    # x-amzn-mqtt-ca on port 443), else 8883.
    host, port = ctx.endpoint_host(endpoint_host, 443 if _io.is_alpn_available() else 8883)
    _wait_for_dns(host, port)
    conn = mqtt_connection_builder.mtls_from_path(
        endpoint=host,
        port=port,
        cert_filepath=cert_path,
        pri_key_filepath=key_path,
        client_id=client_id,
        clean_session=True,
        keep_alive_secs=30,
    )
    # Same eventual-consistency window as the paho path: retry CONNACK on a bounded
    # deadline instead of a fixed pre-sleep.
    connect_deadline = time.time() + 60
    last_exc = None
    while True:
        try:
            conn.connect().result(timeout=30)
            break
        except Exception as exc:  # noqa: BLE001 - retried below, reported if it never clears
            last_exc = exc
            if time.time() >= connect_deadline:
                raise AssertionError(
                    f"MQTT (awsiotsdk) never connected to {host}:{port} within 60s: "
                    f"{last_exc!r}"
                ) from last_exc
            time.sleep(3)
    try:
        sub_future, _ = conn.subscribe(
            topic=topic, qos=_mqtt.QoS.AT_LEAST_ONCE, callback=on_message
        )
        sub_future.result(timeout=30)
        pub_future, _ = conn.publish(
            topic=topic, payload=payload, qos=_mqtt.QoS.AT_LEAST_ONCE
        )
        pub_future.result(timeout=30)
        deadline = time.time() + 30
        while time.time() < deadline and not received["ok"]:
            time.sleep(0.5)
    finally:
        try:
            conn.disconnect().result(timeout=10)
        except Exception:
            pass
    return received["ok"]

@tags("axis:happy-path", "cap:c6", "concern:data-plane", "concern:eventing", "dp:native", "plane:data")
def run(ctx) -> None:
    """A certificate whose policy allows Connect/Subscribe/Publish/Receive publishes over the
    iot:Data-ATS MQTT broker and receives its own message on the subscribed topic."""
    iot = ctx.client("iot")

    # Pick whichever MQTT client library is importable, else fail (never skip).
    try:
        import awscrt  # noqa: F401
        import awsiot  # noqa: F401
        mqtt_fn = _mqtt_awsiotsdk
    except Exception:
        try:
            import paho.mqtt.client  # noqa: F401
            mqtt_fn = _mqtt_paho
        except Exception:
            raise AssertionError(
                "no MQTT client available (install awsiotsdk or paho-mqtt)"
            ) from None

    endpoint_host = iot.describe_endpoint(endpointType="iot:Data-ATS")[
        "endpointAddress"
    ]

    resource_tags = [{"Key": "sim2real", "Value": CHECK}]

    # Provision a cert + key.
    cert = iot.create_keys_and_certificate(setAsActive=True)
    cert_id = cert["certificateId"]
    cert_arn = cert["certificateArn"]
    # Certificates are not a taggable resource type for TagResource (AWS: "Invalid resource
    # type in ARN: cert"); the registered cleanup is what removes it.
    ctx.on_cleanup(lambda: _delete_certificate(iot, cert_id))

    # A policy that permits the MQTT data-plane actions, attached to the cert.
    policy_name = ctx.unique_name("sim2real-behav-policy-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iot:*", "Resource": "*"}],
    }
    iot.create_policy(
        policyName=policy_name, policyDocument=json.dumps(policy_doc), tags=resource_tags
    )
    ctx.on_cleanup(lambda: _delete_policy(iot, policy_name))
    iot.attach_policy(policyName=policy_name, target=cert_arn)

    cert_file = tempfile.NamedTemporaryFile(
        prefix="sim2real-iot-cert-", suffix=".pem", delete=False, mode="w"
    )
    key_file = tempfile.NamedTemporaryFile(
        prefix="sim2real-iot-key-", suffix=".pem", delete=False, mode="w"
    )
    try:
        cert_file.write(cert["certificatePem"])
        cert_file.close()
        key_file.write(cert["keyPair"]["PrivateKey"])
        key_file.close()

        topic = f"sim2real/behav/{ctx.unique_name('sim2real-behav-t-')}"
        payload = b"sim2real-behavioral-iot-payload"
        client_id = ctx.unique_name("sim2real-behav-mqtt-")

        # The client is chosen and imported, the cert is provisioned and its policy attached, so
        # anything the MQTT leg raises from here is the BROKER, including paho's own
        # "Connection refused" / TLS / timeout wording; it is reported as a failed assertion.
        try:
            received = mqtt_fn(
                ctx, endpoint_host, cert_file.name, key_file.name, topic, payload, client_id
            )
        except AssertionError:
            raise
        except Exception as exc:  # noqa: BLE001 — the broker leg failed; say so as a verdict
            raise AssertionError(
                f"{DATAPLANE_MARKER}: MQTT publish/subscribe against {endpoint_host} "
                f"failed: {type(exc).__name__}: {exc}"
            ) from exc
        if not received:
            # Connect, subscribe and publish all succeeded — the broker is reachable and simply
            # never delivered the message.
            _dp_fail(f"message published to {topic} was not received by the subscriber")
    finally:
        for path in (cert_file.name, key_file.name):
            try:
                os.unlink(path)
            except Exception:
                pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
