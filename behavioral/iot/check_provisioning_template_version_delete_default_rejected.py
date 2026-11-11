"""provisioning-template-version-delete-default-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "provisioning-template-version-delete-default-rejected"
GROUP = "state-machine"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a provisioning template's default version fails with InvalidRequestException and
    leaves it the default; after promoting another version, the identical delete succeeds."""
    iot = ctx.client("iot")
    iam = ctx.client("iam")

    role_arn = _create_provisioning_role(ctx, iam)
    template_name = ctx.unique_name("sim2real-prov-tpl-rej-")
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
    default_version_id = created["defaultVersionId"]

    body_v2 = _template_body("ThingNameV2")
    v2 = iot.create_provisioning_template_version(templateName=template_name, templateBody=body_v2)

    code, message = _error_code(
        lambda: iot.delete_provisioning_template_version(templateName=template_name, versionId=default_version_id)
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    expected = f"Unable to delete template version {default_version_id}, it is the default version"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    versions_after = {
        v["versionId"] for v in iot.list_provisioning_template_versions(templateName=template_name)["versions"]
    }
    assert versions_after == {default_version_id, v2["versionId"]}, (
        f"expected both versions to survive the rejected delete, got {versions_after!r}"
    )
    still_default = iot.describe_provisioning_template_version(templateName=template_name, versionId=default_version_id)
    assert still_default["isDefaultVersion"] is True, "default version must remain marked default after the rejected delete"

    iot.update_provisioning_template(templateName=template_name, defaultVersionId=v2["versionId"])

    iot.delete_provisioning_template_version(templateName=template_name, versionId=default_version_id)
    remaining = {
        v["versionId"] for v in iot.list_provisioning_template_versions(templateName=template_name)["versions"]
    }
    assert remaining == {v2["versionId"]}, f"expected only {v2['versionId']!r} to remain, got {remaining!r}"


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
    role_name = ctx.unique_name("sim2real-iot-prov-rej-role-")
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
