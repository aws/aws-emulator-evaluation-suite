"""create-integration-resource-property-conflict-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-integration-resource-property-conflict-rejected"
GROUP = "negative-classes"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateIntegrationResourceProperty with neither processing property is a ValidationException.

    The op is an upsert, so a second call for the same ResourceArn succeeds and overwrites the role.

    Reference: https://docs.aws.amazon.com/glue/latest/dg/aws-glue-api-integrations.html
    """
    glue = ctx.client("glue")
    if not hasattr(glue, "create_integration_resource_property"):
        raise AssertionError(
            "installed botocore has no create_integration_resource_property "
            "operation (zero-ETL integrations API is newer than this SDK "
            "build)"
        )
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = _create_glue_assumable_role(ctx)
    role_arn_2 = _create_glue_assumable_role(ctx)

    db_name = ctx.unique_name("sim2real-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    resource_arn = f"arn:aws:glue:{ctx.region}:{account_id}:database/{db_name}"
    glue.tag_resource(ResourceArn=resource_arn, TagsToAdd={"sim2real": CHECK})

    code, message = _error(lambda: glue.create_integration_resource_property(ResourceArn=resource_arn))
    assert code == "ValidationException", f"expected ValidationException for neither property given, got {code}"
    assert message == (
        "Either source processing properties or target processing properties must be provided in the request."
    ), f"unexpected CreateIntegrationResourceProperty message: {message!r}"

    absent_code, absent_message = _error(lambda: glue.get_integration_resource_property(ResourceArn=resource_arn))
    assert absent_code == "EntityNotFoundException", (
        f"expected EntityNotFoundException after rejected create, got {absent_code}"
    )
    assert absent_message == f"The target resource {resource_arn} is not found.", (
        f"unexpected GetIntegrationResourceProperty message: {absent_message!r}"
    )

    # Create is a set/upsert, not create-once: a second call overwrites the stored value.
    created = glue.create_integration_resource_property(
        ResourceArn=resource_arn,
        TargetProcessingProperties={"RoleArn": role_arn},
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: glue.delete_integration_resource_property(ResourceArn=resource_arn)))
    assert created["ResourceArn"] == resource_arn, f"expected ResourceArn {resource_arn}, got {created['ResourceArn']}"

    upserted = glue.create_integration_resource_property(
        ResourceArn=resource_arn,
        TargetProcessingProperties={"RoleArn": role_arn_2},
    )
    assert upserted["ResourceArn"] == resource_arn, (
        f"expected ResourceArn {resource_arn}, got {upserted['ResourceArn']}"
    )

    now = glue.get_integration_resource_property(ResourceArn=resource_arn)
    assert now["TargetProcessingProperties"]["RoleArn"] == role_arn_2, (
        f"expected upsert to overwrite RoleArn to {role_arn_2}, got {now['TargetProcessingProperties'].get('RoleArn')}"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "EntityNotFoundException",
            "ResourceNotFoundException",
        ):
            raise


def _create_glue_assumable_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-integ-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return resp["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
