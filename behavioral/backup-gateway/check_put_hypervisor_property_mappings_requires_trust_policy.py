"""put-hypervisor-property-mappings-requires-trust-policy."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-hypervisor-property-mappings-requires-trust-policy"
GROUP = "overly-permissive"
SERVICES = ["backup-gateway"]

GATEWAY_OUT_OF_DATE = "The specified gateway is out of date."
MAPPINGS_NOT_FOUND = "The hypervisor property mappings is not found."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutHypervisorPropertyMappings on a hypervisor without a gateway fails with
    ValidationException and persists nothing, whether or not the role trusts backup-gateway; a
    malformed role ARN too."""
    bg = ctx.client("backup-gateway")
    iam = ctx.client("iam")
    arn = _create_hypervisor(ctx)

    # Nothing has been configured yet.
    got = _client_error(lambda: bg.get_hypervisor_property_mappings(HypervisorArn=arn))
    assert got == ("ResourceNotFoundException", MAPPINGS_NOT_FOUND), (
        f"expected ResourceNotFoundException before any Put, got {got!r}"
    )

    mappings = [{
        "VmwareCategory": "sim2real-cat",
        "VmwareTagName": "sim2real-tag",
        "AwsTagKey": "sim2real-key",
        "AwsTagValue": "sim2real-value",
    }]

    # Even a role that properly trusts backup-gateway.amazonaws.com cannot make this succeed,
    # because the Hypervisor has no real, up-to-date associated gateway.
    right_role_name = ctx.unique_name("sim2real-bgw-rightrole-")
    right_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "backup-gateway.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    right_role_arn = iam.create_role(
        RoleName=right_role_name, AssumeRolePolicyDocument=json.dumps(right_trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=right_role_name))

    got = _client_error(lambda: bg.put_hypervisor_property_mappings(
        HypervisorArn=arn, VmwareToAwsTagMappings=mappings, IamRoleArn=right_role_arn
    ))
    assert got == ("ValidationException", GATEWAY_OUT_OF_DATE), (
        f"expected ValidationException for a trusting role with no real gateway, got {got!r}"
    )

    # The failed Put must not have persisted anything.
    still_absent = _client_error(lambda: bg.get_hypervisor_property_mappings(HypervisorArn=arn))
    assert still_absent == ("ResourceNotFoundException", MAPPINGS_NOT_FOUND), (
        f"expected ResourceNotFoundException after the rejected Put, got {still_absent!r}"
    )

    # A syntactically valid role that does not trust backup-gateway.amazonaws.com gets the same
    # ValidationException as a trusting role, not AccessDeniedException.
    wrong_role_name = ctx.unique_name("sim2real-bgw-wrongrole-")
    wrong_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    wrong_role_arn = iam.create_role(
        RoleName=wrong_role_name, AssumeRolePolicyDocument=json.dumps(wrong_trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=wrong_role_name))

    wrong_trust = _client_error(lambda: bg.put_hypervisor_property_mappings(
        HypervisorArn=arn, VmwareToAwsTagMappings=mappings, IamRoleArn=wrong_role_arn
    ))
    assert wrong_trust == ("ValidationException", GATEWAY_OUT_OF_DATE), (
        f"expected ValidationException for a role that does not trust "
        f"backup-gateway.amazonaws.com, got {wrong_trust!r}"
    )

    # Still nothing persisted.
    still_absent_2 = _client_error(lambda: bg.get_hypervisor_property_mappings(HypervisorArn=arn))
    assert still_absent_2 == ("ResourceNotFoundException", MAPPINGS_NOT_FOUND), (
        f"expected ResourceNotFoundException after the untrusted-role Put, got {still_absent_2!r}"
    )

    # A malformed IamRoleArn is rejected with ValidationException too, and not persisted either.
    malformed_role = "not-a-valid-role-arn-string"
    malformed = _client_error(lambda: bg.put_hypervisor_property_mappings(
        HypervisorArn=arn,
        VmwareToAwsTagMappings=mappings,
        IamRoleArn=malformed_role,
    ))
    malformed_message = (
        f"1 validation error detected: Value '{malformed_role}' at 'iamRoleArn' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: "
        r"arn:(aws|aws-cn|aws-us-gov):iam::([0-9]+):role/(\S+)"
    )
    assert malformed == ("ValidationException", malformed_message), (
        f"expected ValidationException for a malformed IamRoleArn, got {malformed!r}"
    )
    malformed_absent = _client_error(lambda: bg.get_hypervisor_property_mappings(HypervisorArn=arn))
    assert malformed_absent == ("ResourceNotFoundException", MAPPINGS_NOT_FOUND), (
        f"expected ResourceNotFoundException after the malformed-arn Put, got {malformed_absent!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    so accepting a request AWS refuses fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_hypervisor(ctx, host=None, name=None):
    bg = ctx.client("backup-gateway")
    kwargs = {
        "Name": name or ctx.unique_name("sim2real-bgw-"),
        "Host": host or f"{ctx.unique_name('sim2real-bgw-host-')}.example.com",
        "Username": "sim2real-user",
        "Password": "Sim2Real-Passw0rd!",
    }
    arn = bg.import_hypervisor_configuration(**kwargs)["HypervisorArn"]

    def _cleanup():
        try:
            bg.delete_hypervisor(HypervisorArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
