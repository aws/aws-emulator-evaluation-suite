"""provisioning-template-version-lifecycle."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "provisioning-template-version-lifecycle"
GROUP = "state-machine"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second template version gets a new non-default id; deleting it leaves only version 1, and after
    DeleteProvisioningTemplate the template, its version 1 and a further mutation all fail
    ResourceNotFoundException with AWS's exact messages."""
    iot = ctx.client("iot")
    iam = ctx.client("iam")

    role_arn = _create_provisioning_role(ctx, iam)
    template_name = ctx.unique_name("sim2real-prov-tpl-")
    body_v1 = _template_body("ThingNameV1")

    created = _retry_while(
        lambda: iot.create_provisioning_template(
            templateName=template_name,
            templateBody=body_v1,
            provisioningRoleArn=role_arn,
            tags=[{"Key": "sim2real", "Value": CHECK}],
        ),
        retry_codes={"InvalidRequestException"},
        timeout_s=20.0,
    )
    ctx.on_cleanup(lambda: _delete_template_quiet(iot, template_name))
    assert created["defaultVersionId"] == 1, (
        f"expected a freshly created template's default version to be 1, got {created['defaultVersionId']!r}"
    )

    body_v2 = _template_body("ThingNameV2")
    v2 = iot.create_provisioning_template_version(templateName=template_name, templateBody=body_v2)
    assert v2["versionId"] != 1, f"expected the new version id to differ from 1, got {v2['versionId']!r}"
    assert v2["isDefaultVersion"] is False, (
        f"expected the new version to not be default, got isDefaultVersion={v2['isDefaultVersion']!r}"
    )

    versions = {v["versionId"] for v in iot.list_provisioning_template_versions(templateName=template_name)["versions"]}
    assert versions == {1, v2["versionId"]}, f"expected versions {{1, {v2['versionId']}}}, got {versions!r}"

    iot.delete_provisioning_template_version(templateName=template_name, versionId=v2["versionId"])
    remaining = {v["versionId"] for v in iot.list_provisioning_template_versions(templateName=template_name)["versions"]}
    assert remaining == {1}, f"expected only version 1 to remain after deleting version {v2['versionId']}, got {remaining!r}"

    iot.delete_provisioning_template(templateName=template_name)

    code, message = _error_code(lambda: iot.describe_provisioning_template(templateName=template_name))
    assert code == "ResourceNotFoundException", f"expected the deleted template to 404, got {code!r}"
    expected = f"Unable to find template named {template_name}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code, message = _error_code(lambda: iot.describe_provisioning_template_version(templateName=template_name, versionId=1))
    assert code == "ResourceNotFoundException", f"expected the deleted template's version 1 to 404, got {code!r}"
    expected = f"Unable to find a template named {template_name}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code, message = _error_code(
        lambda: iot.create_provisioning_template_version(templateName=template_name, templateBody=body_v1)
    )
    assert code == "ResourceNotFoundException", (
        f"expected a mutation against the deleted template to fail not-found, got {code!r}"
    )
    expected = f"Unable to find template named {template_name}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _template_body(thing_name_placeholder_default):
    return json.dumps(
        {
            "Parameters": {"ThingName": {"Type": "String", "Default": thing_name_placeholder_default}},
            "Resources": {
                "thing": {"Type": "AWS::IoT::Thing", "Properties": {"ThingName": {"Ref": "ThingName"}}},
                "certificate": {
                    "Type": "AWS::IoT::Certificate",
                    "Properties": {
                        "CertificateId": {"Ref": "AWS::IoT::Certificate::Id"},
                        "Status": "ACTIVE",
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
    )


def _error_code(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _retry_while(fn, retry_codes, timeout_s=20.0, interval_s=2.0):
    import time

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in retry_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_provisioning_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-iot-prov-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role_quiet(iam, role_name))
    return role["Arn"]


def _delete_role_quiet(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_template_quiet(iot, template_name):
    try:
        for v in iot.list_provisioning_template_versions(templateName=template_name)["versions"]:
            if not v["isDefaultVersion"]:
                try:
                    iot.delete_provisioning_template_version(templateName=template_name, versionId=v["versionId"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
        iot.delete_provisioning_template(templateName=template_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
