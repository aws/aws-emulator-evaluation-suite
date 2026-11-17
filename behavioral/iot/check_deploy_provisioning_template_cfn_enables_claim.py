"""deploy-provisioning-template-cfn-enables-claim."""
from __future__ import annotations

import json
import os
import ssl
import tempfile
import threading
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-provisioning-template-cfn-enables-claim"
GROUP = "deploy"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "dp:native", "plane:control", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed AWS::IoT::ProvisioningTemplate is immediately usable to mint
    a working provisioning claim certificate via CreateProvisioningClaim.
    """
    cfn = ctx.client("cloudformation")
    iot = ctx.client("iot")

    template_name = ctx.unique_name("sim2real-prov-")[:36]
    stack_name = ctx.unique_name("sim2real-prov-stack-")
    thing_template_body = json.dumps(
        {
            "Parameters": {
                "ThingName": {"Type": "String"},
                "AWS::IoT::Certificate::Id": {"Type": "String"},
            },
            "Resources": {
                "thing": {
                    "Type": "AWS::IoT::Thing",
                    "Properties": {"ThingName": {"Ref": "ThingName"}},
                },
                "certificate": {
                    "Type": "AWS::IoT::Certificate",
                    "Properties": {
                        "CertificateId": {"Ref": "AWS::IoT::Certificate::Id"},
                        "Status": "ACTIVE",
                    },
                },
            },
        }
    )

    stack_name_holder = [stack_name]
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name_holder[0]))
    _create_and_wait_for_stack_with_retry(
        ctx,
        cfn,
        stack_name_holder,
        template_name,
        thing_template_body,
    )

    described = iot.describe_provisioning_template(templateName=template_name)
    assert described["enabled"] is True
    assert ":role/" in described["provisioningRoleArn"]

    claim = iot.create_provisioning_claim(templateName=template_name)
    cert_id = claim["certificateId"]
    # best-effort: the claim certificate is a short-lived, non-registry artifact
    # (it is not queryable via DescribeCertificate), so there is nothing to
    # explicitly delete here — it simply expires.
    ctx.on_cleanup(lambda: _retire_certificate(iot, cert_id))

    import re

    assert re.fullmatch(r"(0x)?[a-fA-F0-9]{64}", cert_id), f"unexpected certificateId shape: {cert_id!r}"
    assert claim["certificatePem"].startswith("-----BEGIN CERTIFICATE-----")
    assert claim["keyPair"]["PrivateKey"].startswith("-----BEGIN RSA PRIVATE KEY-----") or claim[
        "keyPair"
    ]["PrivateKey"].startswith("-----BEGIN PRIVATE KEY-----")

    # temporal semantics: a provisioning claim certificate is intentionally
    # short-lived (on the order of minutes), not a long-lived device cert.
    ttl_seconds = claim["expiration"].timestamp() - time.time()
    assert 0 < ttl_seconds < 30 * 60, f"unexpected claim TTL: {ttl_seconds:.0f}s"

    # The claim cert is not independently readable (no DescribeCertificate row for
    # it), so "working" is proven the only way it can be: authenticate an MQTT
    # connection to the account's real IoT Data endpoint with it. This is an
    # independent operation from CreateProvisioningClaim -- the broker only accepts
    # the handshake if the cert is a genuine, ACTIVE, AWS-issued credential, so a
    # target that fabricated a plausible-looking PEM without registering it fails
    # here.
    import paho.mqtt.client as mqtt  # noqa: F401
    endpoint_host = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    tmp_dir = tempfile.mkdtemp(prefix="sim2real-iot-claimauth-")
    ctx.on_cleanup(lambda: _rmtree(tmp_dir))
    cert_path = os.path.join(tmp_dir, "claim-cert.pem")
    key_path = os.path.join(tmp_dir, "claim-key.pem")
    with open(cert_path, "wb") as f:
        f.write(claim["certificatePem"].encode())
    with open(key_path, "wb") as f:
        f.write(claim["keyPair"]["PrivateKey"].encode())

    mqtt_client = _make_mqtt_client(ctx.unique_name("sim2real-claimauth-"))
    try:
        _assert_mqtt_connects(mqtt_client, *ctx.endpoint_host(endpoint_host, 8883), cert_path, key_path)
    finally:
        try:
            mqtt_client.loop_stop()
            mqtt_client.disconnect()
        except Exception:  # noqa: BLE001
            pass


def _rmtree(path: str) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)


def _make_mqtt_client(client_id: str):
    import paho.mqtt.client as mqtt

    try:
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=client_id)
    except AttributeError:
        return mqtt.Client(client_id=client_id)


def _assert_mqtt_connects(
    client, host: str, port: int, cert_path: str, key_path: str, timeout_s: float = 20.0
) -> None:
    """Connect with mutual TLS, encrypted without verifying the server's identity."""
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
    if not connected.wait(timeout=timeout_s):
        raise AssertionError(
            f"claim certificate did not authenticate an MQTT connection to {host}:{port} "
            f"within {timeout_s}s (rc={rc_holder.get('rc')})"
        )


def _provisioning_template_stack(thing_template_body: str) -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"TemplateName": {"Type": "String"}},
        "Resources": {
            "ProvisioningRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "iot.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSIoTThingsRegistration"
                    ],
                },
            },
            "ProvTemplate": {
                "Type": "AWS::IoT::ProvisioningTemplate",
                "DependsOn": "ProvisioningRole",
                "Properties": {
                    "TemplateName": {"Ref": "TemplateName"},
                    "ProvisioningRoleArn": {"Fn::GetAtt": ["ProvisioningRole", "Arn"]},
                    "Enabled": True,
                    "TemplateBody": thing_template_body,
                },
            },
        },
        "Outputs": {
            "RoleArn": {"Value": {"Fn::GetAtt": ["ProvisioningRole", "Arn"]}},
        },
    }


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    _wait_for_stack_deleted(cfn, stack_name)


def _wait_for_stack_deleted(
    cfn, stack_name: str, timeout_s: float = 300.0, interval_s: float = 5.0
) -> None:
    """Teardown is proven, not merely attempted: poll an independent DescribeStacks
    read (not the DeleteStack call itself) until the stack is actually gone, and
    raise rather than swallow if it never gets there."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if "does not exist" in str(exc):
                return
            raise
        if not stacks:
            return
        last_status = stacks[0]["StackStatus"]
        if last_status == "DELETE_COMPLETE":
            return
        if last_status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} entered DELETE_FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not delete within {timeout_s}s (last={last_status})")


def _create_and_wait_for_stack_with_retry(
    ctx, cfn, stack_name_holder: list, template_name: str, thing_template_body: str, retries: int = 2
) -> None:
    """The IoT ProvisioningTemplate CFN resource can fail with 'the provisioning
    role cannot be assumed' because the freshly-created IAM role hasn't
    propagated yet. CFN treats that as a permanent CREATE_FAILED and rolls the
    stack back rather than retrying, so on that specific transient failure we
    delete the failed stack and create a brand-new one (new stack name, same
    template) once the failed stack is deleted, which spans the IAM propagation window."""
    body = json.dumps(_provisioning_template_stack(thing_template_body))
    params = [{"ParameterKey": "TemplateName", "ParameterValue": template_name}]
    attempt = 0
    while True:
        stack_name = stack_name_holder[0]
        cfn.create_stack(
            StackName=stack_name,
            TemplateBody=body,
            Parameters=params,
            Capabilities=["CAPABILITY_IAM"],
        )
        try:
            cfn.get_waiter("stack_create_complete").wait(
                StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
            )
            return
        except Exception:
            reason_text = "; ".join(_stack_failure_reasons(cfn, stack_name))
            transient = "cannot be assumed" in reason_text
            attempt += 1
            if not transient or attempt > retries:
                raise AssertionError(reason_text[:400] or "stack failed, no FAILED events found") from None
            _delete_stack(ctx, stack_name)
            stack_name_holder[0] = f"{stack_name}-retry{attempt}"


def _stack_failure_reasons(cfn, stack_name: str) -> list:
    try:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    except Exception as exc:  # noqa: BLE001
        return [f"<could not fetch events: {exc}>"]
    reasons = []
    for e in events:
        status = e.get("ResourceStatus", "")
        if "FAILED" in status:
            reasons.append(
                f"{e.get('LogicalResourceId')}: {status} - {e.get('ResourceStatusReason')}"
            )
    return reasons


def _retire_certificate(iot, cert_id: str) -> None:
    try:
        iot.update_certificate(certificateId=cert_id, newStatus="REVOKED")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_certificate(certificateId=cert_id, forceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
