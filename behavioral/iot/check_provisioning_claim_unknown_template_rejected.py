"""provisioning-claim-unknown-template-rejected."""
from __future__ import annotations

import json
import time
from datetime import timezone

from cryptography import x509

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "provisioning-claim-unknown-template-rejected"
GROUP = "e2e"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateProvisioningClaim with an unknown template fails with ResourceNotFoundException
    and its exact message, while a real template returns an Amazon-issued certificate whose
    NotAfter matches the reported expiration."""
    iot = ctx.client("iot")
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-prov-role-")
    role_arn = _create_provisioning_role(ctx, iam, role_name)

    real_template_name = ctx.unique_name("sim2real-prov-")[:36]
    missing_template_name = ctx.unique_name("sim2real-prov-missing-")[:36]
    body = json.dumps(
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

    try:
        _create_provisioning_template_with_retry(
            iot,
            templateName=real_template_name,
            templateBody=body,
            provisioningRoleArn=role_arn,
            enabled=True,
            tags=[{"Key": "sim2real", "Value": "true"}],
        )
    except Exception as exc:  # noqa: BLE001
        msg = getattr(exc, "response", {}).get("Error", {}).get("Message", str(exc))
        raise AssertionError(msg) from None
    ctx.on_cleanup(lambda: iot.delete_provisioning_template(templateName=real_template_name))

    code, message = _error_code_and_message(
        lambda: iot.create_provisioning_claim(templateName=missing_template_name)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"Unable to find template named {missing_template_name}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control: the identical operation against a template that really exists succeeds.
    claim = _wait_for_claim(iot, real_template_name)
    new_cert_id = claim["certificateId"]
    ctx.on_cleanup(lambda: _retire_certificate(iot, new_cert_id))
    try:
        iot.tag_resource(
            resourceArn=f"arn:aws:iot:{ctx.region}:{account_id}:cert/{new_cert_id}",
            tags=[{"Key": "sim2real", "Value": "true"}],
        )
    except Exception:  # noqa: BLE001 — best-effort; tagging failure is not the subject under test
        pass

    # terminal read: no AWS reader exists for this id (see docstring), so the consequence we can
    # verify is that the certificate bytes AWS actually signed agree with the expiration the API
    # separately reported, and were issued by Amazon's own IoT PKI -- not fabricable by a stub
    # that merely echoes an input back.
    cert = x509.load_pem_x509_certificate(claim["certificatePem"].encode())
    not_after = _as_utc(getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after)
    api_expiration = _as_utc(claim["expiration"])
    delta_s = abs((not_after - api_expiration).total_seconds())
    assert delta_s < 60, (
        f"certificate NotAfter {not_after} disagrees with API-reported expiration {api_expiration} "
        f"by {delta_s}s"
    )
    issuer = cert.issuer.rfc4514_string()
    assert "Amazon" in issuer, f"expected an Amazon-issued certificate, got issuer {issuer!r}"


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError("expected the call to raise a ClientError, but it succeeded")


def _as_utc(dt):
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _create_provisioning_role(ctx, iam, role_name: str) -> str:
    trust = {
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSIoTThingsRegistration",
    )

    def _cleanup_role():
        try:
            iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSIoTThingsRegistration",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)
    return role_arn


def _wait_for_claim(iot, template_name: str, timeout_s: float = 30.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return iot.create_provisioning_claim(templateName=template_name)
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(2)
    raise last_exc


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
