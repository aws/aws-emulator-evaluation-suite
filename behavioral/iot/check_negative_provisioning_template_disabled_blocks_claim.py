"""negative-provisioning-template-disabled-blocks-claim."""
from __future__ import annotations

import json
import os
import ssl
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "negative-provisioning-template-disabled-blocks-claim"
GROUP = "overly-permissive"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:native", "plane:data")
def run(ctx) -> None:
    """CreateProvisioningClaim issues a claim certificate even for a disabled template, while fleet
    provisioning by claim over `$aws/provisioning-templates/{template}/provision/json` is rejected
    while the template is disabled and succeeds once it is re-enabled."""
    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        raise AssertionError(
            "paho-mqtt is not installed in this environment; cannot perform the "
            "native MQTT fleet-provisioning-by-claim round-trip."
        )

    iot = ctx.client("iot")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-provisioning-role")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = role["Role"]["Arn"]
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSIoTThingsRegistration",
    )
    ctx.on_cleanup(lambda: iam.detach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSIoTThingsRegistration"
    ))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    template_name = ctx.unique_name("sim2real-provtemplate").replace("_", "-")[:36]
    thing_prefix = ctx.unique_name("sim2real-provthing")

    def _template_body():
        return json.dumps(
            {
                "Parameters": {"SerialNumber": {"Type": "String"}},
                "Resources": {
                    "certificate": {
                        "Type": "AWS::IoT::Certificate",
                        "Properties": {
                            "CertificateId": {"Ref": "AWS::IoT::Certificate::Id"},
                            "Status": "ACTIVE",
                        },
                    },
                    "thing": {
                        "Type": "AWS::IoT::Thing",
                        "Properties": {
                            "ThingName": {"Fn::Join": ["", [f"{thing_prefix}-", {"Ref": "SerialNumber"}]]}
                        },
                    },
                },
            }
        )

    def _create_template():
        return iot.create_provisioning_template(
            templateName=template_name,
            templateBody=_template_body(),
            provisioningRoleArn=role_arn,
            enabled=False,
        )

    # Give IAM a moment to propagate before IoT is asked to reference the role.
    _retry(_create_template, exceptions=(ClientError,), attempts=6, delay_s=3.0)
    ctx.on_cleanup(lambda: iot.delete_provisioning_template(templateName=template_name))

    described = iot.describe_provisioning_template(templateName=template_name)
    assert described["enabled"] is False

    # CreateProvisioningClaim itself succeeds regardless of enabled -- the
    # claim certificate is just a bearer credential, not a gate.
    claim = iot.create_provisioning_claim(templateName=template_name)
    claim_cert_id = claim["certificateId"]
    ctx.on_cleanup(lambda: iot.delete_certificate(certificateId=claim_cert_id, forceDelete=True))

    created_things = []
    created_certs = []

    def _cleanup_created():
        for cid in created_certs:
            try:
                iot.update_certificate(certificateId=cid, newStatus="INACTIVE")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
            try:
                iot.delete_certificate(certificateId=cid, forceDelete=True)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        for tname in created_things:
            try:
                iot.delete_thing(thingName=tname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup_created)

    endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    cert_dir = tempfile.mkdtemp(prefix="sim2real-iot-claim-")
    cert_path = os.path.join(cert_dir, "cert.pem")
    key_path = os.path.join(cert_dir, "key.pem")
    with open(cert_path, "w") as f:
        f.write(claim["certificatePem"])
    with open(key_path, "w") as f:
        f.write(claim["keyPair"]["PrivateKey"])

    def _mqtt_provision(serial_number: str):
        """Runs the fleet-provisioning-by-claim MQTT dance once. Returns
        (accepted_payload, rejected_payload)."""
        state = {
            "connected": False,
            "subscribed": 0,
            "create_accepted": None,
            "create_rejected": None,
            "reg_accepted": None,
            "reg_rejected": None,
        }

        def on_connect(client, userdata, flags, rc):
            state["connected"] = rc == 0

        def on_subscribe(client, userdata, mid, granted_qos):
            # A single subscribe() call with N topic filters yields ONE SUBACK
            # packet whose granted_qos carries N entries -- on_subscribe fires
            # once per packet, not once per topic.
            state["subscribed"] += len(granted_qos)

        def on_message(client, userdata, msg):
            if msg.topic == "$aws/certificates/create/json/accepted":
                state["create_accepted"] = json.loads(msg.payload)
            elif msg.topic == "$aws/certificates/create/json/rejected":
                state["create_rejected"] = json.loads(msg.payload)
            elif msg.topic.endswith("/provision/json/accepted"):
                state["reg_accepted"] = json.loads(msg.payload)
            elif msg.topic.endswith("/provision/json/rejected"):
                state["reg_rejected"] = json.loads(msg.payload)

        client_id = ctx.unique_name("s2rmqttclaim")
        try:
            mclient = mqtt.Client(
                client_id=client_id,
                protocol=mqtt.MQTTv311,
                callback_api_version=mqtt.CallbackAPIVersion.VERSION1,
            )
        except (AttributeError, TypeError):
            mclient = mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv311)
        mclient.on_connect = on_connect
        mclient.on_subscribe = on_subscribe
        mclient.on_message = on_message

        ssl_ctx = ssl._create_unverified_context()
        ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        mclient.tls_set_context(ssl_ctx)

        mclient.connect(*ctx.endpoint_host(endpoint, 8883), keepalive=60)
        mclient.loop_start()
        try:
            _poll_until(lambda: state["connected"], timeout_s=20.0, desc="MQTT CONNACK")

            reg_topic_base = f"$aws/provisioning-templates/{template_name}/provision/json"
            mclient.subscribe(
                [
                    ("$aws/certificates/create/json/accepted", 1),
                    ("$aws/certificates/create/json/rejected", 1),
                    (f"{reg_topic_base}/accepted", 1),
                    (f"{reg_topic_base}/rejected", 1),
                ]
            )
            _poll_until(lambda: state["subscribed"] >= 4, timeout_s=15.0, desc="SUBACK x4")

            mclient.publish("$aws/certificates/create/json", "{}", qos=1)
            _poll_until(
                lambda: state["create_accepted"] is not None or state["create_rejected"] is not None,
                timeout_s=30.0,
                desc="CreateKeysAndCertificate ack",
            )
            assert state["create_rejected"] is None, state["create_rejected"]
            token = state["create_accepted"]["certificateOwnershipToken"]
            created_certs.append(state["create_accepted"]["certificateId"])

            reg_payload = {
                "certificateOwnershipToken": token,
                "parameters": {"SerialNumber": serial_number},
            }
            mclient.publish(reg_topic_base, json.dumps(reg_payload), qos=1)
            _poll_until(
                lambda: state["reg_accepted"] is not None or state["reg_rejected"] is not None,
                timeout_s=30.0,
                desc="RegisterThing ack",
            )
            if state["reg_accepted"] is not None:
                created_things.append(f"{thing_prefix}-{serial_number}")
            return state["reg_accepted"], state["reg_rejected"]
        finally:
            mclient.loop_stop()
            mclient.disconnect()

    # While the template is disabled, registering through it is rejected --
    # not silently accepted with a usable thing/certificate.
    accepted, rejected = _mqtt_provision("disabled-001")
    assert accepted is None, f"registration through a disabled template was accepted: {accepted!r}"
    assert rejected is not None, "expected a /provision/json/rejected message while disabled"

    # Independent read at the destination -- the rejected MQTT ack alone could
    # be a lie the target tells over the same channel that just tried the
    # mutation. Confirm no thing actually landed in the registry.
    disabled_thing_name = f"{thing_prefix}-disabled-001"
    try:
        iot.describe_thing(thingName=disabled_thing_name)
    except ClientError as e:
        assert e.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException for {disabled_thing_name}, got {e.response['Error']}"
        )
    else:
        raise AssertionError(
            f"thing {disabled_thing_name} exists in the registry even though registration "
            "through the disabled template was rejected over MQTT"
        )

    # Re-enable the template; the exact same MQTT registration flow now
    # succeeds.
    iot.update_provisioning_template(templateName=template_name, enabled=True)
    described_after = iot.describe_provisioning_template(templateName=template_name)
    assert described_after["enabled"] is True

    accepted2, rejected2 = _mqtt_provision("enabled-001")
    assert rejected2 is None, f"registration through a re-enabled template was rejected: {rejected2!r}"
    assert accepted2 is not None
    assert accepted2["thingName"] == f"{thing_prefix}-enabled-001"

    # Terminal read is independent of the MQTT round trip that performed the
    # mutation: confirm the thing genuinely exists in the registry, not just
    # that the provisioning topic echoed a name back.
    described_registered_thing = iot.describe_thing(thingName=accepted2["thingName"])
    assert described_registered_thing["thingName"] == f"{thing_prefix}-enabled-001", described_registered_thing


def _poll_until(predicate, *, timeout_s: float, interval_s: float = 1.0, desc: str = "condition") -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for: {desc}")


def _retry(fn, *, exceptions, attempts: int, delay_s: float):
    last_exc = None
    for i in range(attempts):
        try:
            return fn()
        except exceptions as e:  # noqa: PERF203 - small bounded retry loop
            last_exc = e
            if i == attempts - 1:
                raise
            time.sleep(delay_s)
    raise last_exc  # pragma: no cover


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

