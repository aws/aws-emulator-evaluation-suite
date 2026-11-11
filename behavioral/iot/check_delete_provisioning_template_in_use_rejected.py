"""delete-provisioning-template-in-use-rejected."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-provisioning-template-in-use-rejected"
GROUP = "overly-permissive"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteProvisioningTemplate is rejected with DeleteConflictException while
    a registered CA certificate's registrationConfig still references the
    template for JITP, and succeeds once that CA certificate is removed."""
    ca_pem = _generate_self_signed_ca_pem()

    iot = ctx.client("iot")
    role_arn = _create_provisioning_role(ctx)

    template_name = ctx.unique_name("sim2realjitp-")
    body = json.dumps(
        {
            "Parameters": {
                "AWS::IoT::Certificate::CommonName": {"Type": "String"},
                "AWS::IoT::Certificate::Id": {"Type": "String"},
            },
            "Resources": {
                "thing": {
                    "Type": "AWS::IoT::Thing",
                    "Properties": {"ThingName": {"Ref": "AWS::IoT::Certificate::CommonName"}},
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
    _retry_on_codes(
        lambda: iot.create_provisioning_template(
            templateName=template_name,
            templateBody=body,
            provisioningRoleArn=role_arn,
            type="JITP",
            tags=[{"Key": "sim2real", "Value": CHECK}],
        ),
        codes=("InvalidRequestException", "UnauthorizedException"),
        timeout_s=45,
    )
    ctx.on_cleanup(lambda: _delete_template_quiet(iot, template_name))

    ca_resp = iot.register_ca_certificate(
        caCertificate=ca_pem,
        certificateMode="SNI_ONLY",
        setAsActive=False,
        allowAutoRegistration=True,
        registrationConfig={"templateName": template_name},
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ca_id = ca_resp["certificateId"]
    ctx.on_cleanup(lambda: _safe_delete_ca(iot, ca_id))

    code, message = _error_code(lambda: iot.delete_provisioning_template(templateName=template_name))
    assert code == "DeleteConflictException", (
        f"expected DeleteConflictException while a registered CA cert still references the "
        f"template for JITP; got {code!r}"
    )
    expected_message = (
        f"The template {template_name} cannot be deleted as it is associated with one or more "
        "CAs for auto registration."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # the template is unaffected by the rejected delete
    still_there = iot.describe_provisioning_template(templateName=template_name)
    assert still_there["templateName"] == template_name, (
        f"the rejected delete must leave the template in place; expected {template_name!r}, "
        f"got {still_there.get('templateName')!r}"
    )

    # release the reference: deactivate and delete the referencing CA cert
    iot.delete_ca_certificate(certificateId=ca_id)

    # positive control: deletion now succeeds once nothing references the template
    _retry_on_codes(
        lambda: iot.delete_provisioning_template(templateName=template_name),
        codes=("DeleteConflictException",),
        timeout_s=30,
    )
    not_found_code, not_found_message = _error_code(
        lambda: iot.describe_provisioning_template(templateName=template_name)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"the template must be gone once nothing references it; expected "
        f"ResourceNotFoundException from an independent describe, got {not_found_code!r}"
    )
    expected_not_found = f"Unable to find template named {template_name}"
    assert not_found_message == expected_not_found, (
        f"expected message {expected_not_found!r}, got {not_found_message!r}"
    )


def _generate_self_signed_ca_pem() -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-iot-jitp-ca")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _create_provisioning_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-iot-jitp-role-")
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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSIoTThingsRegistration"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _delete_template_quiet(iot, template_name):
    """Teardown: delete the template, tolerating one the check body already deleted."""
    try:
        iot.delete_provisioning_template(templateName=template_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_ca(iot, ca_id):
    try:
        iot.delete_ca_certificate(certificateId=ca_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _retry_on_codes(fn, codes, timeout_s: float = 45.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in codes:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _error_code(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
