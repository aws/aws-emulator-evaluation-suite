"""provisioning-template-json-body-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "provisioning-template-json-body-round-trip"
GROUP = "representation"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A provisioning template body with nested unicode strings and numeric fields is
    stored and returned byte-identical (structurally) by DescribeProvisioningTemplate."""
    iot = ctx.client("iot")
    role_arn = _create_provisioning_role(ctx)

    template_body = {
        "Parameters": {
            "SerialNumber": {"Type": "String"},
            "AWS::IoT::Certificate::Id": {"Type": "String"},
        },
        # "Mappings" is an opaque nested key/value store the provisioning-template
        # engine does not deep-validate the same way it validates "Resources" (which
        # must conform to the AWS::IoT::Thing/Certificate/Policy schemas) -- it is a
        # realistic place a real fleet-provisioning template stores unicode/numeric
        # device metadata that must survive storage byte-identical.
        "Mappings": {
            "DeviceDefaults": {
                "config": {
                    "note": "caf\u00e9 \u65e5\u672c\u8a9e \U0001F6F0",
                    "count": 42,
                    "ratio": 3.14159,
                }
            }
        },
        "Resources": {
            "thing": {
                "Type": "AWS::IoT::Thing",
                "Properties": {
                    "ThingName": {"Ref": "SerialNumber"},
                    "AttributePayload": {"note": "caf\u00e9 \u65e5\u672c\u8a9e \U0001F6F0"},
                },
            },
            # a provisioning template must declare a certificate resource -- use an
            # existing certificate ID (never resolved, since this template is never
            # actually provisioned against) purely to satisfy that structural
            # requirement. CertificateId must Ref the special JITP parameter name.
            "certificate": {
                "Type": "AWS::IoT::Certificate",
                "Properties": {
                    "CertificateId": {"Ref": "AWS::IoT::Certificate::Id"},
                    "Status": "ACTIVE",
                },
            },
        },
    }
    body_str = json.dumps(template_body, ensure_ascii=False)

    name = ctx.unique_name("sim2realProvTmpl")
    _create_template_with_retry(iot, name, body_str, role_arn)
    ctx.on_cleanup(lambda: iot.delete_provisioning_template(templateName=name))

    described = iot.describe_provisioning_template(templateName=name)
    _assert_json_identical(json.loads(described["templateBody"]), template_body)


def _assert_json_identical(actual, expected, path="$"):
    # dict/list/scalar equality in Python treats 42 == 42.0, so a plain `==`
    # on the parsed structures cannot detect the target silently widening an
    # int to a float (or otherwise changing type) -- which is exactly the
    # "byte-identical (structurally)" claim this check makes. Walk both trees
    # and require the same type at every node, not just an equal value.
    assert type(actual) is type(expected), (
        f"type mismatch at {path}: expected {type(expected).__name__} "
        f"({expected!r}), got {type(actual).__name__} ({actual!r})"
    )
    if isinstance(expected, dict):
        assert set(actual) == set(expected), (
            f"key mismatch at {path}: expected {sorted(expected)}, got {sorted(actual)}"
        )
        for key in expected:
            _assert_json_identical(actual[key], expected[key], f"{path}.{key}")
    elif isinstance(expected, list):
        assert len(actual) == len(expected), (
            f"length mismatch at {path}: expected {len(expected)}, got {len(actual)}"
        )
        for i, (a, e) in enumerate(zip(actual, expected)):
            _assert_json_identical(a, e, f"{path}[{i}]")
    else:
        assert actual == expected, f"value mismatch at {path}: expected {expected!r}, got {actual!r}"


def _create_provisioning_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-iot-provrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "iot.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role["Arn"]


def _create_template_with_retry(iot, name, body_str, role_arn, timeout_s=30.0, interval_s=2.0):
    # a freshly created IAM role can take a few seconds to be usable as
    # provisioningRoleArn elsewhere in AWS; poll the actual create call rather than
    # sleeping a fixed duration.
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iot.create_provisioning_template(
                templateName=name, templateBody=body_str, provisioningRoleArn=role_arn
            )
            return
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
