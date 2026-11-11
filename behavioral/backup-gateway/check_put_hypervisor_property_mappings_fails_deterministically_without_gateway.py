"""put-hypervisor-property-mappings-fails-deterministically-without-gateway."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-hypervisor-property-mappings-fails-deterministically-without-gateway"
GROUP = "state"
SERVICES = ["backup-gateway"]

GATEWAY_OUT_OF_DATE = "The specified gateway is out of date."
MAPPINGS_NOT_FOUND = "The hypervisor property mappings is not found."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutHypervisorPropertyMappings on a hypervisor without a gateway fails with the same
    ValidationException on every attempt, and GetHypervisorPropertyMappings stays
    ResourceNotFound."""
    bg = ctx.client("backup-gateway")
    iam = ctx.client("iam")

    role_arn = _create_trusting_role(ctx, iam)
    arn = _create_hypervisor(ctx)

    mapping_a = [{
        "VmwareCategory": "sim2real-cat-a",
        "VmwareTagName": "tag-a",
        "AwsTagKey": "sim2real-a-key",
        "AwsTagValue": "a-value",
    }]

    # First attempt: deterministically rejected (no real, associated gateway backs this
    # Hypervisor), nothing persisted.
    first_put = _client_error(lambda: bg.put_hypervisor_property_mappings(
        HypervisorArn=arn, VmwareToAwsTagMappings=mapping_a, IamRoleArn=role_arn
    ))
    assert first_put == ("ValidationException", GATEWAY_OUT_OF_DATE), \
        f"expected ValidationException {GATEWAY_OUT_OF_DATE!r} on first Put, got {first_put!r}"
    first_get = _client_error(lambda: bg.get_hypervisor_property_mappings(HypervisorArn=arn))
    assert first_get == ("ResourceNotFoundException", MAPPINGS_NOT_FOUND), \
        f"expected ResourceNotFoundException after failed first Put, got {first_get!r}"

    # Second, identical attempt: same error, not a transient success and not a different error
    # family (e.g. no AccessDeniedException/ConflictException surfacing on retry).
    second_put = _client_error(lambda: bg.put_hypervisor_property_mappings(
        HypervisorArn=arn, VmwareToAwsTagMappings=mapping_a, IamRoleArn=role_arn
    ))
    assert second_put == ("ValidationException", GATEWAY_OUT_OF_DATE), \
        f"expected ValidationException {GATEWAY_OUT_OF_DATE!r} on second, identical Put, got {second_put!r}"
    second_get = _client_error(lambda: bg.get_hypervisor_property_mappings(HypervisorArn=arn))
    assert second_get == ("ResourceNotFoundException", MAPPINGS_NOT_FOUND), \
        f"expected ResourceNotFoundException after failed second Put, got {second_get!r}"


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
        "Tags": [{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
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


def _create_trusting_role(ctx, iam):
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "backup-gateway.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_name = ctx.unique_name("sim2real-bgw-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

