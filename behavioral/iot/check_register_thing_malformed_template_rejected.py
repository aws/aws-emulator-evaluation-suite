"""register-thing-malformed-template-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "register-thing-malformed-template-rejected"
GROUP = "e2e"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterThing with a syntactically broken templateBody is rejected with
    InvalidRequestException, the bogus thing is never created, while an otherwise
    identical, well-formed RegisterThing call in the same file succeeds."""
    iot = ctx.client("iot")

    keys = iot.create_keys_and_certificate(setAsActive=True)
    cert_id = keys["certificateId"]
    ctx.on_cleanup(lambda: _delete_cert(iot, cert_id))

    good_template = json.dumps(
        {
            "Parameters": {"ThingName": {"Type": "String"}, "CertificateId": {"Type": "String"}},
            "Resources": {
                "thing": {"Type": "AWS::IoT::Thing", "Properties": {"ThingName": {"Ref": "ThingName"}}},
                "certificate": {
                    "Type": "AWS::IoT::Certificate",
                    "Properties": {"CertificateId": {"Ref": "CertificateId"}, "Status": "ACTIVE"},
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
    )

    # positive control: a well-formed RegisterThing call succeeds and creates the thing
    good_thing_name = ctx.unique_name("sim2real-iot-thing-good-")
    register = iot.register_thing(templateBody=good_template, parameters={"ThingName": good_thing_name, "CertificateId": cert_id})
    resource_arns = register["resourceArns"]
    ctx.on_cleanup(lambda: _cleanup_registered_thing(iot, good_thing_name, resource_arns))
    described = iot.describe_thing(thingName=good_thing_name)
    assert described["thingArn"] == resource_arns["thing"], (
        f"expected describe_thing({good_thing_name!r}) to report thingArn "
        f"{resource_arns['thing']!r}, got {described['thingArn']!r}"
    )

    # negative: syntactically broken JSON templateBody is rejected
    bad_thing_name = ctx.unique_name("sim2real-iot-thing-bad-")
    malformed_template = "{ this is not valid json "
    code, message = _error_code(
        lambda: iot.register_thing(templateBody=malformed_template, parameters={"ThingName": bad_thing_name, "CertificateId": cert_id}),
        on_success="RegisterThing accepted a syntactically broken templateBody instead of rejecting it",
    )
    assert code == "InvalidRequestException", (
        f"expected RegisterThing to reject the malformed templateBody with "
        f"InvalidRequestException, got {code!r}"
    )
    expected = (
        "Invalid registration template. Template format error: JSON syntax error at line 1, column 3"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the bad thing was never created
    not_found_code, message = _error_code(
        lambda: iot.describe_thing(thingName=bad_thing_name),
        on_success=(
            f"describe_thing({bad_thing_name!r}) found a thing that the rejected "
            "RegisterThing call should never have created"
        ),
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"expected describe_thing({bad_thing_name!r}) to fail with "
        f"ResourceNotFoundException, got {not_found_code!r}"
    )
    expected = f"Thing {ctx.account}:{bad_thing_name} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error_code(fn, *, on_success: str):
    """Call fn(); return its botocore (error code, message). An unexpected SUCCESS raises, because
    an emulator accepting/reporting something real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"{on_success}: {result!r}")


def _delete_cert(iot, cert_id):
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


def _cleanup_registered_thing(iot, thing_name: str, resource_arns: dict) -> None:
    cert_arn = resource_arns.get("certificate")
    policy_arn = resource_arns.get("policy")
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
