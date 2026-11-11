"""create-provisioning-claim-missing-template-rejected."""
from __future__ import annotations

import json
import os
import shutil
import socket
import ssl
import tempfile
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-provisioning-claim-missing-template-rejected"
GROUP = "negative-classes"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:native", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateProvisioningClaim with a nonexistent template fails with
    ResourceNotFoundException and its exact message and adds no certificate; a real
    template mints one that completes an mTLS handshake."""
    iot = ctx.client("iot")
    iam = ctx.client("iam")

    missing_template = ctx.unique_name("sim2real-notmpl-")

    certs_before = _certificate_ids(iot)
    err = _error(lambda: iot.create_provisioning_claim(templateName=missing_template))
    assert err == ("ResourceNotFoundException", f"Unable to find template named {missing_template}"), err
    certs_after_rejection = _certificate_ids(iot)
    assert certs_after_rejection == certs_before, (
        f"a certificate was minted despite the claim being rejected: "
        f"before={certs_before!r} after={certs_after_rejection!r}"
    )

    # positive control: a real template that exists and is enabled
    role_arn = _create_provisioning_role(ctx, iam, ctx.unique_name("sim2real-provrole-"))
    policy_name = ctx.unique_name("sim2real-provpolicy-")
    iot.create_policy(
        policyName=policy_name,
        policyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "iot:Connect", "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iot.delete_policy(policyName=policy_name))

    template_name = ctx.unique_name("sim2real-provtmpl-")
    template_body = json.dumps(_minimal_provisioning_template_body(policy_name))
    # CreateProvisioningTemplate can transiently fail with InvalidRequestException
    # ("provisioning role cannot be assumed") right after the role is created, while
    # the new role propagates through IAM. Retry on that specific signal only.
    _create_provisioning_template_with_retry(
        iot,
        templateName=template_name,
        templateBody=template_body,
        provisioningRoleArn=role_arn,
        enabled=True,
    )
    ctx.on_cleanup(lambda: iot.delete_provisioning_template(templateName=template_name))

    claim = iot.create_provisioning_claim(templateName=template_name)
    assert claim["certificatePem"], "positive control minted no certificate PEM"
    claim_cert_id = claim["certificateId"]
    assert claim_cert_id, "positive control minted no certificate id"
    assert claim_cert_id not in certs_before, (
        f"minted claim certificate id {claim_cert_id!r} collides with a pre-existing certificate"
    )

    def _cleanup_claim_cert() -> None:
        try:
            iot.update_certificate(certificateId=claim_cert_id, newStatus="INACTIVE")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            iot.delete_certificate(certificateId=claim_cert_id, forceDelete=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_claim_cert)

    # terminal read: independent of the mutating CreateProvisioningClaim call, at
    # the destination -- the claim certificate must actually authenticate a real
    # mutual-TLS session against the IoT device gateway, not just be echoed in the
    # claim response. A fresh claim certificate is not visible through
    # DescribeCertificate or ListCertificates, so the only independent read is
    # using it over the data-plane connection it was minted for. An unregistered/bogus certificate is rejected by AWS IoT's
    # device gateway during the TLS handshake itself, before any MQTT framing, so
    # a completed handshake is a genuine destination-level consequence.
    endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    tmp_dir = tempfile.mkdtemp(prefix="sim2real-iot-claim-")
    ctx.on_cleanup(lambda: shutil.rmtree(tmp_dir, ignore_errors=True))
    cert_path = os.path.join(tmp_dir, "claim-cert.pem")
    key_path = os.path.join(tmp_dir, "claim-key.pem")
    with open(cert_path, "w") as f:
        f.write(claim["certificatePem"])
    with open(key_path, "w") as f:
        f.write(claim["keyPair"]["PrivateKey"])

    _assert_mtls_handshake_succeeds(ctx, endpoint, cert_path, key_path)


def _error(fn):
    """Call fn(); return its (error code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


def _assert_mtls_handshake_succeeds(ctx, endpoint: str, cert_path: str, key_path: str) -> None:
    ssl_ctx = ssl._create_unverified_context()
    ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    try:
        with socket.create_connection(ctx.endpoint_host(endpoint, 8883), timeout=20) as sock:
            with ssl_ctx.wrap_socket(sock, server_hostname=endpoint) as tls_sock:
                cipher = tls_sock.cipher()
    except (ssl.SSLError, ConnectionError) as exc:
        raise AssertionError(
            f"mTLS handshake using the minted claim certificate failed against "
            f"{endpoint}:8883 -- the certificate was not accepted: {exc}"
        ) from None
    assert cipher, "mTLS handshake completed but negotiated no cipher"


def _poll_until(predicate, *, timeout_s: float, interval_s: float, description: str) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s")


def _certificate_ids(iot) -> set:
    ids = set()
    paginator = iot.get_paginator("list_certificates")
    for page in paginator.paginate():
        for cert in page.get("certificates", []):
            ids.add(cert["certificateId"])
    return ids


def _create_provisioning_template_with_retry(iot, timeout_s: float = 30.0, **kwargs) -> None:
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


def _minimal_provisioning_template_body(policy_name: str) -> dict:
    return {
        "Parameters": {"SerialNumber": {"Type": "String"}},
        "Resources": {
            "thing": {
                "Type": "AWS::IoT::Thing",
                "Properties": {"ThingName": {"Ref": "SerialNumber"}},
            },
            "certificate": {
                "Type": "AWS::IoT::Certificate",
                "Properties": {
                    "CertificateId": {"Ref": "AWS::IoT::Certificate::Id"},
                    "Status": "ACTIVE",
                },
            },
            "policy": {
                "Type": "AWS::IoT::Policy",
                "Properties": {"PolicyName": policy_name},
            },
        },
    }


def _create_provisioning_role(ctx, iam, role_name: str) -> str:
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "iot.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSIoTThingsRegistration",
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSIoTThingsRegistration",
        )
    )
    return role["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
