"""e2e-provisioning-claim-to-thing-registration."""
from __future__ import annotations

import json
import os
import ssl
import tempfile
import threading
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-provisioning-claim-to-thing-registration"
GROUP = "e2e"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c3", "cap:c6", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:native", "plane:data")
def run(ctx) -> None:
    """A claim certificate from CreateProvisioningClaim drives the MQTT fleet-provisioning
    topics to register a new thing with the expected name and an ACTIVE certificate."""
    import paho.mqtt.client as mqtt  # noqa: F401

    iam = ctx.client("iam")
    iot = ctx.client("iot")

    role_name = ctx.unique_name("sim2real-fleetprov-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "fleetprov"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSIoTThingsRegistration"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn))

    template_name = ctx.unique_name("sim2real-fleetprov-tmpl-")
    device_template_body = json.dumps(
        {
            "Parameters": {"SerialNumber": {"Type": "String"}},
            "Resources": {
                "certificate": {
                    "Type": "AWS::IoT::Certificate",
                    "Properties": {"CertificateId": {"Ref": "AWS::IoT::Certificate::Id"}, "Status": "Active"},
                },
                "policy": {
                    "Type": "AWS::IoT::Policy",
                    "Properties": {
                        "PolicyDocument": json.dumps(
                            {
                                "Version": "2012-10-17",
                                "Statement": [{"Effect": "Allow", "Action": "iot:Connect", "Resource": "*"}],
                            }
                        )
                    },
                },
                "thing": {
                    "Type": "AWS::IoT::Thing",
                    "Properties": {
                        "ThingName": {"Fn::Join": ["", ["sim2real-device-", {"Ref": "SerialNumber"}]]}
                    },
                },
            },
        }
    )
    _create_provisioning_template_with_retry(
        iot,
        templateName=template_name,
        templateBody=device_template_body,
        provisioningRoleArn=role_arn,
        enabled=True,
        tags=[{"Key": "sim2real", "Value": "fleetprov"}],
    )
    ctx.on_cleanup(lambda: iot.delete_provisioning_template(templateName=template_name))

    claim = iot.create_provisioning_claim(templateName=template_name)
    claim_cert_id = claim["certificateId"]
    claim_cert_pem = claim["certificatePem"]
    claim_private_key = claim["keyPair"]["PrivateKey"]
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    claim_cert_arn = f"arn:aws:iot:{ctx.region}:{account_id}:cert/{claim_cert_id}"
    try:
        iot.tag_resource(resourceArn=claim_cert_arn, tags=[{"Key": "sim2real", "Value": "fleetprov"}])
    except Exception:  # noqa: BLE001 - tagging is best-effort, not the assertion under test
        pass

    def _cleanup_claim_cert() -> None:
        # A claim certificate is short-lived; once it expires IoT answers ResourceNotFoundException.
        try:
            iot.update_certificate(certificateId=claim_cert_id, newStatus="INACTIVE")
            iot.delete_certificate(certificateId=claim_cert_id, forceDelete=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_claim_cert)

    endpoint_host = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]

    tmp_dir = tempfile.mkdtemp(prefix="sim2real-iot-fleetprov-")
    ctx.on_cleanup(lambda: _rmtree(tmp_dir))
    cert_path = os.path.join(tmp_dir, "claim-cert.pem")
    key_path = os.path.join(tmp_dir, "claim-key.pem")
    with open(cert_path, "wb") as f:
        f.write(claim_cert_pem.encode())
    with open(key_path, "wb") as f:
        f.write(claim_private_key.encode())

    client = _make_mqtt_client(ctx.unique_name("sim2real-claim-"))
    resource_arns: dict = {}
    try:
        _mqtt_connect(client, *ctx.endpoint_host(endpoint_host, 8883), cert_path, key_path)

        _, create_payload = _mqtt_request(
            client,
            "$aws/certificates/create/json",
            "{}",
            ["$aws/certificates/create/json/accepted", "$aws/certificates/create/json/rejected"],
        )
        create_resp = json.loads(create_payload)
        assert "certificateOwnershipToken" in create_resp, f"cert creation rejected: {create_resp}"
        ownership_token = create_resp["certificateOwnershipToken"]
        new_cert_id = create_resp["certificateId"]

        serial_number = ctx.unique_name("SN-")
        provision_topic = f"$aws/provisioning-templates/{template_name}/provision/json"
        _, provision_payload = _mqtt_request(
            client,
            provision_topic,
            json.dumps(
                {"certificateOwnershipToken": ownership_token, "parameters": {"SerialNumber": serial_number}}
            ),
            [f"{provision_topic}/accepted", f"{provision_topic}/rejected"],
        )
        provision_resp = json.loads(provision_payload)
        assert "thingName" in provision_resp, f"RegisterThing through the claim was rejected: {provision_resp}"
        thing_name = provision_resp["thingName"]
        resource_arns = provision_resp.get("resourceArns", {})
        for arn in resource_arns.values():
            try:
                iot.tag_resource(resourceArn=arn, tags=[{"Key": "sim2real", "Value": "fleetprov"}])
            except Exception:  # noqa: BLE001 - tagging is best-effort, not the assertion under test
                pass
    finally:
        try:
            client.loop_stop()
            client.disconnect()
        except Exception:  # noqa: BLE001
            pass
        ctx.on_cleanup(lambda ra=dict(resource_arns): _cleanup_registered_device(iot, ra))

    expected_thing_name = f"sim2real-device-{serial_number}"
    assert thing_name == expected_thing_name

    described_thing = iot.describe_thing(thingName=thing_name)
    assert described_thing["thingName"] == thing_name

    described_cert = iot.describe_certificate(certificateId=new_cert_id)
    assert described_cert["certificateDescription"]["status"] == "ACTIVE"


def _create_provisioning_template_with_retry(iot, timeout_s: float = 30.0, **kwargs) -> None:
    """CreateProvisioningTemplate can transiently fail with InvalidRequestException
    ("provisioning role cannot be assumed") right after the role is created, while
    the new role propagates through IAM."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iot.create_provisioning_template(**kwargs)
            return
        except Exception as exc:  # noqa: BLE001
            msg = getattr(exc, "response", {}).get("Error", {}).get("Message", "")
            if "cannot be assumed" in msg and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _rmtree(path: str) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)


def _make_mqtt_client(client_id: str):
    import paho.mqtt.client as mqtt

    try:
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=client_id)
    except AttributeError:
        return mqtt.Client(client_id=client_id)


def _mqtt_connect(client, host: str, port: int, cert_path: str, key_path: str) -> None:
    connected = threading.Event()
    rc_holder: dict = {}

    def on_connect(_c, _u, _f, rc):
        rc_holder["rc"] = rc
        if rc == 0:
            connected.set()

    client.on_connect = on_connect
    client.tls_set(cert_reqs=ssl.CERT_NONE, certfile=cert_path, keyfile=key_path)
    client.connect(host, port, keepalive=30)
    client.loop_start()
    if not connected.wait(timeout=20):
        client.loop_stop()
        raise AssertionError(f"MQTT connect to {host}:{port} timed out (rc={rc_holder.get('rc')})")


def _mqtt_request(
    client, request_topic: str, request_payload: str, response_topics: list[str], timeout_s: float = 25
):
    import paho.mqtt.client as mqtt

    got = threading.Event()
    box: dict = {}
    subscribed = threading.Event()
    pending_mids: set = set()

    def on_message(_c, _u, msg):
        if not got.is_set():
            box["topic"] = msg.topic
            box["payload"] = msg.payload
            got.set()

    def on_subscribe(_c, _u, mid, _granted_qos):
        pending_mids.discard(mid)
        if not pending_mids:
            subscribed.set()

    client.on_message = on_message
    client.on_subscribe = on_subscribe
    for topic in response_topics:
        result, mid = client.subscribe(topic, qos=1)
        assert result == mqtt.MQTT_ERR_SUCCESS, f"subscribe to {topic} failed: rc={result}"
        pending_mids.add(mid)
    if not subscribed.wait(timeout=10):
        raise AssertionError(f"no SUBACK for {response_topics} within 10s (rc pending: {pending_mids})")
    client.publish(request_topic, request_payload, qos=1)
    if not got.wait(timeout=timeout_s):
        raise AssertionError(f"no MQTT response on {response_topics} within {timeout_s}s")
    return box["topic"], box["payload"]


def _cleanup_registered_device(iot, resource_arns: dict) -> None:
    thing_name = None
    cert_id = None
    policy_name = None
    cert_arn = None
    for arn in resource_arns.values():
        res = arn.rsplit(":", 1)[-1]
        if "/" not in res:
            continue
        res_type, res_name = res.split("/", 1)
        if res_type == "thing":
            thing_name = res_name
        elif res_type == "cert":
            cert_id = res_name
            cert_arn = arn
        elif res_type == "policy":
            policy_name = res_name
    if thing_name and cert_arn:
        try:
            iot.detach_thing_principal(thingName=thing_name, principal=cert_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    if policy_name and cert_arn:
        iot.detach_policy(policyName=policy_name, target=cert_arn)
    if thing_name:
        try:
            iot.delete_thing(thingName=thing_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    if cert_id:
        try:
            iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
            iot.delete_certificate(certificateId=cert_id, forceDelete=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    if policy_name:
        try:
            iot.delete_policy(policyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
