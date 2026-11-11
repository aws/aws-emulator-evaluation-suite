"""representation-provisioning-template-json-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "representation-provisioning-template-json-round-trip"
GROUP = "representation"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A provisioning template body with nested JSON parameters and non-ASCII mustache-style
    attribute values round-trips byte-identical across CreateProvisioningTemplate and
    CreateProvisioningTemplateVersion retrieval -- each version keeps its own exact body."""
    iot = ctx.client("iot")
    role_arn = _create_provisioning_role(ctx)

    template_name = ctx.unique_name("sim2realprov")[:36].rstrip("-_")
    body_v1 = _template_body("v1-区域-☂️-😀")
    created = _create_template_with_retry(iot, template_name, body_v1, role_arn)
    ctx.on_cleanup(lambda: iot.delete_provisioning_template(templateName=template_name))

    desc_v1 = iot.describe_provisioning_template_version(
        templateName=template_name, versionId=created["defaultVersionId"]
    )
    assert desc_v1["templateBody"] == body_v1, (
        f"expected v1 body {body_v1!r}, DescribeProvisioningTemplateVersion returned "
        f"{desc_v1['templateBody']!r}"
    )

    body_v2 = _template_body("v2-мир-☂️-🎉")
    created_v2 = iot.create_provisioning_template_version(
        templateName=template_name, templateBody=body_v2, setAsDefault=False
    )
    ctx.on_cleanup(
        lambda: iot.delete_provisioning_template_version(
            templateName=template_name, versionId=created_v2["versionId"]
        )
    )

    desc_v2 = iot.describe_provisioning_template_version(
        templateName=template_name, versionId=created_v2["versionId"]
    )
    assert desc_v2["templateBody"] == body_v2, (
        f"expected v2 body {body_v2!r}, DescribeProvisioningTemplateVersion returned "
        f"{desc_v2['templateBody']!r}"
    )
    assert desc_v2["templateBody"] != body_v1, (
        f"v2 body must differ from v1 body, but both versions returned {desc_v2['templateBody']!r}"
    )

    # The original version must still be exactly what was first created.
    desc_v1_again = iot.describe_provisioning_template_version(
        templateName=template_name, versionId=created["defaultVersionId"]
    )
    assert desc_v1_again["templateBody"] == body_v1, (
        f"expected v1 body {body_v1!r} to survive creation of v2 unchanged, "
        f"DescribeProvisioningTemplateVersion returned {desc_v1_again['templateBody']!r}"
    )


def _template_body(marker: str) -> str:
    doc = {
        "Parameters": {
            "SerialNumber": {"Type": "String"},
            "Location": {"Type": "String", "Default": marker},
            "AWS::IoT::Certificate::Id": {"Type": "String"},
        },
        "Resources": {
            "thing": {
                "Type": "AWS::IoT::Thing",
                "Properties": {
                    "ThingName": {"Ref": "SerialNumber"},
                    "AttributePayload": {"version": "v1", "serialNumber": {"Ref": "SerialNumber"}},
                    "ThingGroups": ["sim2real-fleet", {"Ref": "Location"}],
                },
            },
            "certificate": {
                "Type": "AWS::IoT::Certificate",
                "Properties": {
                    "CertificateId": {"Ref": "AWS::IoT::Certificate::Id"},
                    "Status": "ACTIVE",
                    "ThingPrincipalType": "EXCLUSIVE_THING",
                },
            },
            "policy": {
                "Type": "AWS::IoT::Policy",
                "Properties": {
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["iot:Connect"],
                                "Resource": ["*"],
                            }
                        ],
                    }
                },
            },
        },
    }
    return json.dumps(doc, ensure_ascii=False, sort_keys=True)


def _create_provisioning_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-iot-provrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSIoTThingsRegistration"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_template_with_retry(iot, template_name: str, template_body: str, role_arn: str, timeout_s: float = 30.0):
    # bounded retry, not a fixed sleep: a freshly created IAM role/trust needs a few
    # seconds to propagate before IoT will accept it as provisioningRoleArn.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return iot.create_provisioning_template(
                templateName=template_name,
                templateBody=template_body,
                provisioningRoleArn=role_arn,
                enabled=True,
                tags=[{"Key": "sim2real", "Value": CHECK}],
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidRequestException":
                raise
            last_exc = exc
            time.sleep(5)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
