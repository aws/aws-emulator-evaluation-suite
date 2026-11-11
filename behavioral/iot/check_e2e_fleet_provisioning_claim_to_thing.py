"""e2e-fleet-provisioning-claim-to-thing."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-fleet-provisioning-claim-to-thing"
GROUP = "e2e"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c3", "concern:e2e", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateProvisioningClaim mints a short-lived PEM claim certificate, and RegisterThing with the
    template and an ACTIVE device certificate creates a describable Thing."""
    iot = ctx.client("iot")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-prov-role-")
    role_arn = _create_provisioning_role(ctx, iam, role_name)

    template_name = ctx.unique_name("sim2real-fleet-")[:36]
    thing_name = ctx.unique_name("sim2real-fleet-thing-")
    template_body = json.dumps(_template_body())

    try:
        _create_provisioning_template_with_retry(
            iot,
            templateName=template_name,
            templateBody=template_body,
            provisioningRoleArn=role_arn,
            enabled=True,
            tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    except Exception as exc:  # noqa: BLE001
        msg = getattr(exc, "response", {}).get("Error", {}).get("Message", str(exc))
        raise AssertionError(msg) from None
    ctx.on_cleanup(lambda: iot.delete_provisioning_template(templateName=template_name))

    # the claim certificate is not a registry-visible principal, so check its shape and TTL
    claim = _wait_for_claim(iot, template_name)
    import re

    assert re.fullmatch(r"(0x)?[a-fA-F0-9]{64}", claim["certificateId"]), (
        f"claim certificateId does not look like a certificate id hash: {claim['certificateId']!r}"
    )
    assert claim["certificatePem"].startswith("-----BEGIN CERTIFICATE-----"), (
        f"claim certificatePem does not start with a PEM header: {claim['certificatePem'][:40]!r}"
    )
    ttl_seconds = claim["expiration"].timestamp() - time.time()
    assert 0 < ttl_seconds < 30 * 60, f"unexpected claim TTL: {ttl_seconds:.0f}s"

    # stands in for the device certificate a device would obtain over MQTT during the handshake
    device_cert = iot.create_keys_and_certificate(setAsActive=True)
    device_cert_id = device_cert["certificateId"]
    ctx.on_cleanup(lambda: _cleanup_certificate(iot, device_cert_id))
    _tag_resource_quiet(iot, device_cert["certificateArn"])

    register_resp = _register_thing_with_retry(
        iot,
        templateBody=template_body,
        parameters={"ThingName": thing_name, "AWS::IoT::Certificate::Id": device_cert_id},
    )
    ctx.on_cleanup(lambda: _cleanup_thing(iot, thing_name))

    expected_thing_arn_suffix = f"thing/{thing_name}"
    assert register_resp["resourceArns"]["thing"].endswith(expected_thing_arn_suffix), (
        f"expected registered thing ARN ending {expected_thing_arn_suffix!r}, "
        f"got {register_resp['resourceArns']['thing']!r}"
    )
    assert register_resp["certificatePem"] == device_cert["certificatePem"], (
        "RegisterThing returned a certificatePem that does not match the device "
        "certificate supplied as AWS::IoT::Certificate::Id"
    )
    _tag_resource_quiet(iot, register_resp["resourceArns"]["thing"])

    described = iot.describe_thing(thingName=thing_name)
    assert described["thingName"] == thing_name, (
        f"expected describe_thing to return thingName {thing_name!r}, got {described['thingName']!r}"
    )

    cert_desc = iot.describe_certificate(certificateId=device_cert_id)["certificateDescription"]
    assert cert_desc["status"] == "ACTIVE", (
        f"expected registered device certificate status ACTIVE, got {cert_desc['status']!r}"
    )



# ===== helpers =====
def _template_body() -> dict:
    return {
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _wait_for_claim(iot, template_name: str, timeout_s: float = 30.0) -> dict:
    """CreateProvisioningClaim can transiently fail with InvalidRequestException
    immediately after CreateProvisioningTemplate while the template propagates."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return iot.create_provisioning_claim(templateName=template_name)
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(2)
    raise last_exc


def _register_thing_with_retry(iot, timeout_s: float = 30.0, **kwargs) -> dict:
    """RegisterThing can transiently fail right after CreateKeysAndCertificate
    while the new certificate propagates through the registry."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return iot.register_thing(**kwargs)
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(3)
    raise last_exc


def _tag_resource_quiet(iot, resource_arn: str) -> None:
    """Tag after creation, since RegisterThing and CreateKeysAndCertificate accept no tags."""
    try:
        iot.tag_resource(resourceArn=resource_arn, tags=[{"Key": "sim2real", "Value": CHECK}])
    except Exception:
        pass


def _cleanup_thing(iot, thing_name: str) -> None:
    try:
        principals = iot.list_thing_principals(thingName=thing_name).get("principals", [])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        principals = []
    for principal in principals:
        try:
            iot.detach_thing_principal(thingName=thing_name, principal=principal)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    try:
        iot.delete_thing(thingName=thing_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _cleanup_certificate(iot, cert_id: str) -> None:
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
