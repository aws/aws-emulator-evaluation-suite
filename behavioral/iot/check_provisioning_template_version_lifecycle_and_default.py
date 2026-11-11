"""provisioning-template-version-lifecycle-and-default."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "provisioning-template-version-lifecycle-and-default"
GROUP = "state-machine"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A version created with setAsDefault becomes version 2 and the template's default; the old default
    version 1 then deletes cleanly (a read and a second delete fail ResourceNotFoundException with the
    exact message) while version 2 stays the default."""
    iot = ctx.client("iot")
    role_arn = _create_provisioning_role(ctx)

    template_name = ctx.unique_name("sim2realprov-")
    body_v1 = _template_body("thing-v1")
    body_v2 = _template_body("thing-v2")

    create_resp = _retry_on_codes(
        lambda: iot.create_provisioning_template(
            templateName=template_name,
            templateBody=body_v1,
            provisioningRoleArn=role_arn,
            tags=[{"Key": "sim2real", "Value": CHECK}],
        ),
        codes=("InvalidRequestException", "UnauthorizedException"),
        timeout_s=45,
    )
    ctx.on_cleanup(lambda: iot.delete_provisioning_template(templateName=template_name))
    assert create_resp["defaultVersionId"] == 1, (
        f"a freshly created template's first version should default to 1, "
        f"got {create_resp['defaultVersionId']}"
    )

    version_resp = iot.create_provisioning_template_version(
        templateName=template_name, templateBody=body_v2, setAsDefault=True
    )
    assert version_resp["versionId"] == 2, (
        f"the second version ever created for this template should be versionId 2, "
        f"got {version_resp['versionId']}"
    )
    assert version_resp["isDefaultVersion"] is True, (
        f"setAsDefault=True should mark v2 as the default immediately, "
        f"got isDefaultVersion={version_resp['isDefaultVersion']}"
    )

    described = iot.describe_provisioning_template(templateName=template_name)
    assert described["defaultVersionId"] == 2, (
        f"describe should reflect the new default version 2, got {described['defaultVersionId']}"
    )

    # version 1 is no longer the default, so it can be removed cleanly
    iot.delete_provisioning_template_version(templateName=template_name, versionId=1)

    code, message = _error_code(
        lambda: iot.describe_provisioning_template_version(
            templateName=template_name, versionId=1
        )
    )
    assert code == "ResourceNotFoundException", (
        f"describing the deleted version 1 should 404, got {code!r}"
    )
    expected = f"Unable to find a template version with ID 1 for template {template_name}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # the deletion is not just hidden from describe -- a second delete of the same
    # already-gone version must fail the same way, proving it is actually gone
    redelete_code, message = _error_code(
        lambda: iot.delete_provisioning_template_version(templateName=template_name, versionId=1)
    )
    assert redelete_code == "ResourceNotFoundException", (
        f"deleting the already-deleted version 1 again should still 404, got {redelete_code!r}"
    )
    expected = "Unable to find template version 1"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # the new default version is unaffected by deleting the old one
    still_default = iot.describe_provisioning_template_version(
        templateName=template_name, versionId=2
    )
    assert still_default["isDefaultVersion"] is True, (
        f"version 2 should remain the default after v1 was deleted, "
        f"got isDefaultVersion={still_default['isDefaultVersion']}"
    )

    final = iot.describe_provisioning_template(templateName=template_name)
    assert final["defaultVersionId"] == 2, (
        f"template default should still be 2 after deleting the old default's "
        f"predecessor, got {final['defaultVersionId']}"
    )


def _template_body(thing_name_default: str) -> str:
    # FLEET_PROVISIONING (the default template type) requires a Certificate
    # resource in addition to a Thing resource, or CreateProvisioningTemplate
    # rejects the body as invalid.
    return json.dumps(
        {
            "Parameters": {
                "ThingName": {"Type": "String", "Default": thing_name_default},
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
                        "Status": "INACTIVE",
                    },
                },
            },
        }
    )


def _create_provisioning_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-iot-prov-role-")
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
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
