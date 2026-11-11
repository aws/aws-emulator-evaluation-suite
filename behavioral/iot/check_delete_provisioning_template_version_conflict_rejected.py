"""delete-provisioning-template-version-conflict-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-provisioning-template-version-conflict-rejected"
GROUP = "negative-classes"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting the default provisioning template version fails with InvalidRequestException and
    keeps it; a non-default version deletes, and once another version is made the default the
    identical delete succeeds."""
    iot = ctx.client("iot")
    iam = ctx.client("iam")

    role_arn = _create_provisioning_role(ctx, iam, ctx.unique_name("sim2real-dptv-role-"))
    policy_name = ctx.unique_name("sim2real-dptv-policy-")
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

    template_name = ctx.unique_name("sim2real-dptv-tmpl-")
    body_v1 = json.dumps(_minimal_provisioning_template_body(policy_name, description="v1"))
    created = _retry_on_codes(
        lambda: iot.create_provisioning_template(
            templateName=template_name,
            templateBody=body_v1,
            provisioningRoleArn=role_arn,
            enabled=True,
        ),
        codes=("InvalidRequestException", "UnauthorizedException"),
        timeout_s=45,
    )
    version1_id = created["defaultVersionId"]
    ctx.on_cleanup(lambda: iot.delete_provisioning_template(templateName=template_name))

    body_v2 = json.dumps(_minimal_provisioning_template_body(policy_name, description="v2"))
    v2 = iot.create_provisioning_template_version(
        templateName=template_name, templateBody=body_v2, setAsDefault=False
    )
    version2_id = v2["versionId"]
    ctx.on_cleanup(
        lambda: _best_effort_delete_version(iot, template_name, version2_id)
    )

    # version1 is still the default: deleting it must be rejected
    code, message = _error_code(
        lambda: iot.delete_provisioning_template_version(
            templateName=template_name, versionId=version1_id
        ),
        description="delete of the default provisioning template version",
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    expected_message = f"Unable to delete template version {version1_id}, it is the default version"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    still_there = iot.describe_provisioning_template_version(
        templateName=template_name, versionId=version1_id
    )
    assert still_there["versionId"] == version1_id, (
        f"expected version {version1_id} to still exist after the rejected delete, "
        f"got {still_there.get('versionId')!r}"
    )

    # positive control: a non-default version deletes cleanly
    v3 = iot.create_provisioning_template_version(
        templateName=template_name,
        templateBody=json.dumps(_minimal_provisioning_template_body(policy_name, description="v3")),
        setAsDefault=False,
    )
    version3_id = v3["versionId"]
    iot.delete_provisioning_template_version(templateName=template_name, versionId=version3_id)
    code_after, message_after = _error_code(
        lambda: iot.describe_provisioning_template_version(
            templateName=template_name, versionId=version3_id
        ),
        description=f"describe of deleted version {version3_id}",
    )
    assert code_after == "ResourceNotFoundException", (
        f"expected version {version3_id} to be gone after delete, got error code {code_after!r}"
    )
    expected_after = f"Unable to find a template version with ID {version3_id} for template {template_name}"
    assert message_after == expected_after, f"expected message {expected_after!r}, got {message_after!r}"

    iot.update_provisioning_template(templateName=template_name, defaultVersionId=version2_id)
    iot.delete_provisioning_template_version(templateName=template_name, versionId=version1_id)
    code_v1_after, message_v1_after = _error_code(
        lambda: iot.describe_provisioning_template_version(
            templateName=template_name, versionId=version1_id
        ),
        description=f"describe of deleted version {version1_id} (after the default was moved off it)",
    )
    assert code_v1_after == "ResourceNotFoundException", (
        f"expected version {version1_id} to be gone once it was no longer the default "
        f"and the identical delete call was retried, got error code {code_v1_after!r}"
    )
    expected_v1_after = f"Unable to find a template version with ID {version1_id} for template {template_name}"
    assert message_v1_after == expected_v1_after, f"expected message {expected_v1_after!r}, got {message_v1_after!r}"


def _error_code(fn, *, description: str):
    """Call fn(); return its (error code, error message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected {description} to fail, but it SUCCEEDED and returned {result!r}")


def _retry_on_codes(fn, codes, timeout_s: float = 45.0, interval_s: float = 3.0):
    """Bounded retry while a just-created IAM role propagates and IoT cannot yet validate
    provisioningRoleArn."""
    from botocore.exceptions import ClientError

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
    raise AssertionError(f"still failing after {timeout_s}s of IAM role propagation retries: {last_exc}")


def _best_effort_delete_version(iot, template_name: str, version_id) -> None:
    from botocore.exceptions import ClientError

    try:
        iot.delete_provisioning_template_version(templateName=template_name, versionId=version_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise



def _minimal_provisioning_template_body(policy_name: str, description: str) -> dict:
    return {
        "Parameters": {"SerialNumber": {"Type": "String"}},
        "Resources": {
            "thing": {
                "Type": "AWS::IoT::Thing",
                "Properties": {
                    "ThingName": {"Ref": "SerialNumber"},
                    "AttributePayload": {"version": description},
                },
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
    managed_arn = "arn:aws:iam::aws:policy/service-role/AWSIoTThingsRegistration"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_arn))
    return role["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
