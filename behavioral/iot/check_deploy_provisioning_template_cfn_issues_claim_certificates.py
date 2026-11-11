"""deploy-provisioning-template-cfn-issues-claim-certificates."""
from __future__ import annotations

import json
import os
import socket
import ssl
import tempfile
import time

from behavioral_harness import tags

CHECK = "deploy-provisioning-template-cfn-issues-claim-certificates"
GROUP = "deploy"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """A fleet-provisioning template deployed via CloudFormation issues, through
    CreateProvisioningClaim, a structurally valid and already-ACTIVE claim certificate/key
    pair -- not merely a stack that reaches CREATE_COMPLETE."""
    iam = ctx.client("iam")
    cfn = ctx.client("cloudformation")
    iot = ctx.client("iot")

    role_name = ctx.unique_name("sim2real-provtmpl-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSIoTThingsRegistration"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn))

    template_name = ctx.unique_name("sim2real-provtmpl-")
    device_template_body = json.dumps(
        {
            "Parameters": {
                "SerialNumber": {"Type": "String"},
            },
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

    stack_name = ctx.unique_name("sim2real-provtmpl-stack-")
    cfn_template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "ProvTemplate": {
                    "Type": "AWS::IoT::ProvisioningTemplate",
                    "Properties": {
                        "TemplateName": template_name,
                        "ProvisioningRoleArn": role_arn,
                        "TemplateBody": device_template_body,
                        "Enabled": True,
                    },
                }
            },
        }
    )
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=cfn_template,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    _wait_for_stack_create_with_retry(cfn, stack_name, cfn_template)

    described = iot.describe_provisioning_template(templateName=template_name)
    assert described["enabled"] is True, f"expected the CFN-deployed template to be enabled, got {described['enabled']!r}"

    claim = iot.create_provisioning_claim(templateName=template_name)
    certificate_id = claim["certificateId"]
    certificate_pem = claim["certificatePem"]
    private_key = claim["keyPair"]["PrivateKey"]
    public_key = claim["keyPair"]["PublicKey"]

    # A CreateProvisioningClaim certificate is a temporary claim cert, deliberately
    # excluded from the certificate registry (confirmed against real AWS: it never
    # appears via DescribeCertificate/ListCertificates, and it self-expires within
    # minutes) -- there is nothing in the registry to update or delete.

    assert certificate_pem.startswith("-----BEGIN CERTIFICATE-----"), (
        f"claim certificate PEM missing header: {certificate_pem[:40]!r}"
    )
    assert "-----END CERTIFICATE-----" in certificate_pem, "claim certificate PEM missing footer"
    assert "PRIVATE KEY-----" in private_key, f"claim private key not PEM-shaped: {private_key[:40]!r}"
    assert "PUBLIC KEY-----" in public_key, f"claim public key not PEM-shaped: {public_key[:40]!r}"
    assert len(certificate_id) == 64, f"expected a 64-char certificateId, got {len(certificate_id)}: {certificate_id!r}"

    # The claim cert has no independent registry entry to read back, so the only
    # destination-side proof that it is genuinely ACTIVE (not merely a well-formed
    # PEM blob) is that AWS IoT's broker accepts it for mutual TLS -- an inactive or
    # bogus certificate fails the handshake itself, before any MQTT CONNECT.
    endpoint_host = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    _assert_claim_cert_authenticates(ctx, endpoint_host, certificate_pem, private_key)


def _assert_claim_cert_authenticates(ctx, endpoint_host: str, cert_pem: str, key_pem: str) -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        cert_path = os.path.join(tmp_dir, "claim-cert.pem")
        key_path = os.path.join(tmp_dir, "claim-key.pem")
        with open(cert_path, "w") as f:
            f.write(cert_pem)
        with open(key_path, "w") as f:
            f.write(key_pem)
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        tls_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        tls_context.check_hostname = False
        tls_context.verify_mode = ssl.CERT_NONE
        with socket.create_connection(ctx.endpoint_host(endpoint_host, 8883), timeout=15) as sock:
            with tls_context.wrap_socket(sock, server_hostname=endpoint_host) as tls_sock:
                assert tls_sock.version() is not None, (
                    f"mutual TLS handshake against {endpoint_host}:8883 did not complete "
                    "with the claim certificate -- AWS IoT did not accept it as active"
                )


def _delete_stack(cfn, stack_name: str) -> None:
    """Teardown: DeleteStack is idempotent and the waiter treats a missing stack as deleted."""
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


def _wait_for_stack_create_with_retry(cfn, stack_name: str, template_body: str, attempts: int = 3) -> None:
    """A ProvisioningTemplate's ProvisioningRoleArn is validated at creation; a role/managed-
    policy attachment created moments earlier can still be lagging on IAM's eventual-consistency
    window, which rolls the stack back with no useful CFN-level retry. Recreate the stack a few
    times, giving IAM time to propagate, rather than treating that transient rollback as a
    template bug."""
    last_status = None
    last_reason = None
    for attempt in range(attempts):
        try:
            cfn.get_waiter("stack_create_complete").wait(
                StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
            )
            return
        except Exception:  # noqa: BLE001
            events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
            failed = [e for e in events if e.get("ResourceStatus", "").endswith("FAILED")]
            last_reason = failed[0]["ResourceStatusReason"] if failed else "unknown"
            last_status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
            if attempt == attempts - 1:
                raise AssertionError(
                    f"stack failed to reach CREATE_COMPLETE after {attempts} attempts "
                    f"(status={last_status}, reason={last_reason})"
                )
            _delete_stack(cfn, stack_name)
            time.sleep(10 * (attempt + 1))
            cfn.create_stack(
                StackName=stack_name,
                TemplateBody=template_body,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
