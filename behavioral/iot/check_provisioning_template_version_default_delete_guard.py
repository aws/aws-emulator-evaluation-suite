"""provisioning-template-version-default-delete-guard."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "provisioning-template-version-default-delete-guard"
GROUP = "state-machine"
SERVICES = ["iot"]


def _error_code(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _try(fn):
    try:
        return fn()
    except ClientError:
        return None



@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """The default provisioning template version cannot be deleted while it is
    marked default (InvalidRequestException); deletion succeeds only after a
    different version has been promoted to default via UpdateProvisioningTemplate.
    """
    iot = ctx.client("iot")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-provrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    template_name = ctx.unique_name("sim2real-provtpl-")
    policy_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iot:Connect", "Resource": "*"}],
    })
    body_v1 = json.dumps({
        "Parameters": {"ThingName": {"Type": "String"}},
        "Resources": {
            "thing": {"Type": "AWS::IoT::Thing", "Properties": {"ThingName": {"Ref": "ThingName"}}},
            "certificate": {
                "Type": "AWS::IoT::Certificate",
                "Properties": {"CertificateId": {"Ref": "AWS::IoT::Certificate::Id"}, "Status": "ACTIVE"},
            },
            "policy": {"Type": "AWS::IoT::Policy", "Properties": {"PolicyDocument": policy_doc}},
        },
    })
    body_v2 = json.dumps({
        "Parameters": {
            "ThingName": {"Type": "String"},
            "SerialNumber": {"Type": "String"},
        },
        "Resources": {
            "thing": {"Type": "AWS::IoT::Thing", "Properties": {"ThingName": {"Ref": "ThingName"}}},
            "certificate": {
                "Type": "AWS::IoT::Certificate",
                "Properties": {"CertificateId": {"Ref": "AWS::IoT::Certificate::Id"}, "Status": "ACTIVE"},
            },
            "policy": {"Type": "AWS::IoT::Policy", "Properties": {"PolicyDocument": policy_doc}},
        },
    })

    created = _poll_until(
        lambda: _try(
            lambda: iot.create_provisioning_template(
                templateName=template_name,
                templateBody=body_v1,
                provisioningRoleArn=role_arn,
                tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
        ),
        lambda r: r is not None,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert created is not None, "CreateProvisioningTemplate never succeeded (role propagation timeout)"
    ctx.on_cleanup(lambda: _safe_delete_template(iot, template_name))
    default_v1 = created["defaultVersionId"]

    v2 = iot.create_provisioning_template_version(
        templateName=template_name, templateBody=body_v2, setAsDefault=False
    )
    v2_id = v2["versionId"]
    assert v2["isDefaultVersion"] is False, (
        f"expected v2 (versionId={v2_id}) created with setAsDefault=False to not be "
        f"the default, got isDefaultVersion={v2['isDefaultVersion']!r}"
    )

    # Negative: cannot delete the current default version.
    code = None
    msg = None
    try:
        iot.delete_provisioning_template_version(templateName=template_name, versionId=default_v1)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"].get("Message")
    # Empirically this is InvalidRequestException ("... it is the default
    # version"), not DeleteConflictException.
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}: {msg}"
    expected = f"Unable to delete template version {default_v1}, it is the default version"
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # Effect absent: version 1 is still there and still default.
    described_v1 = iot.describe_provisioning_template_version(templateName=template_name, versionId=default_v1)
    assert described_v1["isDefaultVersion"] is True, (
        f"rejected delete must leave v1 (versionId={default_v1}) as the default, "
        f"got isDefaultVersion={described_v1['isDefaultVersion']!r}"
    )

    # Promote v2 to default, which frees v1 up for deletion.
    iot.update_provisioning_template(templateName=template_name, defaultVersionId=v2_id)

    # Positive control: v1 (no longer default) now deletes cleanly.
    iot.delete_provisioning_template_version(templateName=template_name, versionId=default_v1)
    code_v1_gone, message = _error_code(
        lambda: iot.describe_provisioning_template_version(templateName=template_name, versionId=default_v1)
    )
    assert code_v1_gone == "ResourceNotFoundException", (
        f"expected v1 (versionId={default_v1}) to be gone after delete, got code={code_v1_gone!r}"
    )
    expected = f"Unable to find a template version with ID {default_v1} for template {template_name}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # With only the (now default) v2 remaining, the whole template can be removed.
    iot.delete_provisioning_template(templateName=template_name)
    code_tpl_gone, message = _error_code(lambda: iot.describe_provisioning_template(templateName=template_name))
    assert code_tpl_gone == "ResourceNotFoundException", (
        f"expected template {template_name!r} to be gone after delete, got code={code_tpl_gone!r}"
    )
    expected = f"Unable to find template named {template_name}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _safe_delete_template(iot, template_name: str) -> None:
    try:
        iot.delete_provisioning_template(templateName=template_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
