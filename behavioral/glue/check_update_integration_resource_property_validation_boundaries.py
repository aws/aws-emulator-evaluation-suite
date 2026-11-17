"""update-integration-resource-property-validation-boundaries."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-integration-resource-property-validation-boundaries"
GROUP = "negative-classes"
SERVICES = ["glue", "iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateIntegrationResourceProperty with neither processing property, or with a resource ARN
    of an unsupported type, is a ValidationException; a well-formed Glue database ARN with
    TargetProcessingProperties succeeds and the stored value reads back.

    Reference: https://docs.aws.amazon.com/glue/latest/dg/aws-glue-api-integrations.html
    """
    glue = ctx.client("glue")
    role_arn = _create_glue_role(ctx)

    db_name = ctx.unique_name("sim2real-uirp-db-")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    resource_arn = f"arn:aws:glue:{ctx.region}:{ctx.account}:database/{db_name}"

    # Negative: no processing property given at all.
    code1, message1 = _refusal(lambda: glue.update_integration_resource_property(ResourceArn=resource_arn))
    assert code1 == "ValidationException", f"expected ValidationException for neither property, got {code1}"
    assert message1 == (
        "Either source processing properties or target processing properties must be provided in the request."
    ), f"unexpected UpdateIntegrationResourceProperty message: {message1!r}"

    # Effect absent: an independent read (Get, not Update) shows nothing was ever stored.
    absent_code, absent_message = _refusal(lambda: glue.get_integration_resource_property(ResourceArn=resource_arn))
    assert absent_code == "EntityNotFoundException", (
        f"expected EntityNotFoundException after the rejected update, got {absent_code}"
    )
    assert absent_message == f"The target resource {resource_arn} is not found.", (
        f"unexpected GetIntegrationResourceProperty message: {absent_message!r}"
    )

    # Negative: a syntactically valid ARN of a resource type this API does not accept.
    unsupported_arn = f"arn:aws:rds:{ctx.region}:{ctx.account}:cluster:{ctx.unique_name('sim2real-uirp-cluster-')}"
    code2, message2 = _refusal(
        lambda: glue.update_integration_resource_property(
            ResourceArn=unsupported_arn, TargetProcessingProperties={"RoleArn": role_arn}
        )
    )
    assert code2 == "ValidationException", f"expected ValidationException for an unsupported ARN type, got {code2}"
    assert message2 == f"Encountered invalid resource arn {unsupported_arn}", (
        f"unexpected UpdateIntegrationResourceProperty message: {message2!r}"
    )

    # Positive control: a well-formed Glue database ARN with a real processing property succeeds.
    updated = glue.update_integration_resource_property(
        ResourceArn=resource_arn, TargetProcessingProperties={"RoleArn": role_arn}
    )
    ctx.on_cleanup(lambda: _safe_delete_integration_resource_property(glue, resource_arn))
    assert updated["ResourceArn"] == resource_arn, (
        f"expected ResourceArn {resource_arn!r}, got {updated.get('ResourceArn')!r}"
    )

    # Terminal read: independent of the mutating call, at the destination.
    got = glue.get_integration_resource_property(ResourceArn=resource_arn)
    assert got["TargetProcessingProperties"]["RoleArn"] == role_arn, (
        f"expected TargetProcessingProperties.RoleArn {role_arn!r}, got "
        f"{got['TargetProcessingProperties'].get('RoleArn')!r}"
    )


def _refusal(fn):
    """Return the (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete_integration_resource_property(glue, resource_arn):
    try:
        glue.delete_integration_resource_property(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _create_glue_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-uirp-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
