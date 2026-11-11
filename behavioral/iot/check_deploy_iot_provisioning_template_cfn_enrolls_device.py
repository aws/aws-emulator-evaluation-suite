"""deploy-iot-provisioning-template-cfn-enrolls-device."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-iot-provisioning-template-cfn-enrolls-device"
GROUP = "deploy"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::IoT::ProvisioningTemplate can actually be used by
    a real fleet-provisioning claim to register a new Thing with the template's
    defined attributes -- not merely reach CREATE_COMPLETE."""
    iot = ctx.client("iot")
    cfn = ctx.client("cloudformation")

    template_name = ctx.unique_name("sim2realtmpl")[:36]
    thing_name = ctx.unique_name("sim2real-iot-thing-")
    serial_value = ctx.unique_name("SN-")

    # A persisted (CreateProvisioningTemplate-backed) FLEET_PROVISIONING template's certificate
    # resource must reference a certificate that already exists via the "AWS::IoT::Certificate::Id"
    # pseudo-parameter -- real AWS rejects an inline "CertificateSigningRequest" here with "The
    # template body is invalid: CertificateId must contain a reference to
    # AWS::IoT::Certificate::Id". The CSR is still exercised -- just via a real
    # CreateCertificateFromCsr call up front, whose resulting certificateId is what the template
    # references.
    inner_body = {
        "Parameters": {
            "ThingName": {"Type": "String"},
            "AWS::IoT::Certificate::Id": {"Type": "String"},
            "SerialNumber": {"Type": "String"},
        },
        "Resources": {
            "thing": {
                "Type": "AWS::IoT::Thing",
                "Properties": {
                    "ThingName": {"Ref": "ThingName"},
                    "AttributePayload": {"version": "v1", "SerialNumber": {"Ref": "SerialNumber"}},
                },
            },
            "certificate": {
                "Type": "AWS::IoT::Certificate",
                "Properties": {"CertificateId": {"Ref": "AWS::IoT::Certificate::Id"}, "Status": "ACTIVE"},
            },
            "policy": {
                "Type": "AWS::IoT::Policy",
                "Properties": {
                    "PolicyDocument": json.dumps(
                        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iot:Connect", "Resource": "*"}]}
                    )
                },
            },
        },
    }
    inner_body_str = json.dumps(inner_body)


    # Create the provisioning role OUTSIDE of CloudFormation and poll until IoT can
    # actually use it (IAM role trust propagation is eventually-consistent; creating
    # the role inside the same stack/same instant as the ProvisioningTemplate resource
    # causes CloudFormation to roll the whole stack back on the transient permission
    # error). Once a real CreateProvisioningTemplate call succeeds with this role, the
    # role is confirmed usable and CloudFormation's own call will not race it.
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-iot-prov-role-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSIoTThingsRegistration")
    ctx.on_cleanup(lambda: _detach_role_policy(iam, role_name))
    _wait_role_usable(iot, role_arn, inner_body_str, ctx)

    stack_name = ctx.unique_name("sim2real-iot-cfn-")
    stack_template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ProvisioningTemplate": {
                "Type": "AWS::IoT::ProvisioningTemplate",
                "Properties": {
                    "TemplateName": template_name,
                    "ProvisioningRoleArn": role_arn,
                    "Enabled": True,
                    "TemplateBody": inner_body_str,
                },
            },
        },
    }
    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(stack_template))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    described = iot.describe_provisioning_template(templateName=template_name)
    assert described["enabled"] is True, f"expected the CFN-deployed template enabled, got {described['enabled']!r}"

    claim = iot.create_provisioning_claim(templateName=template_name)
    claim_cert_id = claim["certificateId"]
    ctx.on_cleanup(lambda: _cleanup_claim_cert(iot, claim_cert_id))

    csr_pem = _make_csr_pem(thing_name)
    created_cert = iot.create_certificate_from_csr(certificateSigningRequest=csr_pem, setAsActive=True)
    cert_id = created_cert["certificateId"]
    ctx.on_cleanup(lambda: _cleanup_claim_cert(iot, cert_id))

    register = iot.register_thing(
        templateBody=inner_body_str,
        parameters={"ThingName": thing_name, "AWS::IoT::Certificate::Id": cert_id, "SerialNumber": serial_value},
    )
    resource_arns = register["resourceArns"]
    ctx.on_cleanup(lambda: _cleanup_registered_thing(iot, thing_name, resource_arns))

    described_thing = iot.describe_thing(thingName=thing_name)
    assert described_thing["attributes"]["SerialNumber"] == serial_value, (
        f"expected SerialNumber={serial_value!r} on the registered Thing, "
        f"got {described_thing['attributes'].get('SerialNumber')!r}"
    )
    assert described_thing["thingArn"] == resource_arns["thing"], (
        f"describe_thing arn {described_thing['thingArn']!r} != register_thing's own "
        f"resourceArns['thing'] {resource_arns['thing']!r}"
    )



def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


def _make_csr_pem(common_name: str) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(Encoding.PEM).decode("utf-8")


def _cleanup_claim_cert(iot, cert_id: str) -> None:
    try:
        iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_certificate(certificateId=cert_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise



def _delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _detach_role_policy(iam, role_name: str) -> None:
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSIoTThingsRegistration")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_role_usable(iot, role_arn: str, template_body: str, ctx, timeout_s: float = 90.0) -> None:
    """Poll with a real CreateProvisioningTemplate call until IoT can assume the newly
    created role (IAM trust-policy propagation is eventually consistent), deleting the
    probe template each time so no residue is left behind. Only retries the specific
    transient "cannot be assumed" rejection -- any other ClientError (e.g. a malformed
    template body) is a deterministic defect and must fail immediately, not after
    burning the whole timeout window."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        probe_name = ctx.unique_name("sim2real-iot-role-probe-")
        try:
            iot.create_provisioning_template(
                templateName=probe_name,
                provisioningRoleArn=role_arn,
                templateBody=template_body,
            )
            iot.delete_provisioning_template(templateName=probe_name)
            return
        except ClientError as exc:
            msg = exc.response.get("Error", {}).get("Message", "")
            if "cannot be assumed" not in msg:
                raise
            time.sleep(3.0)
    raise AssertionError(f"provisioning role {role_arn} was not usable within {timeout_s}s")


def _cleanup_registered_thing(iot, thing_name: str, resource_arns: dict) -> None:
    cert_arn = resource_arns.get("certificate")
    policy_arn = resource_arns.get("policy")
    cert_id = cert_arn.split("/")[-1] if cert_arn else None
    policy_name = policy_arn.split("/")[-1] if policy_arn else None
    try:
        if cert_arn:
            iot.detach_thing_principal(thingName=thing_name, principal=cert_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    if policy_name and cert_arn:
        iot.detach_policy(policyName=policy_name, target=cert_arn)
    try:
        if cert_id:
            iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
            iot.delete_certificate(certificateId=cert_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        if policy_name:
            iot.delete_policy(policyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_thing(thingName=thing_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
