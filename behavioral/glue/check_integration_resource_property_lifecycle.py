"""integration-resource-property-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "integration-resource-property-lifecycle"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateIntegrationResourceProperty -> GetIntegrationResourceProperty reflects the target
    processing role -> DeleteIntegrationResourceProperty removes it, a subsequent get 404s, and a
    second delete on the now-dead resource also 404s rather than reporting success."""
    glue = ctx.client("glue")
    account = _account_id(ctx)
    db_name = _create_database(ctx, glue)
    resource_arn = f"arn:aws:glue:{ctx.region}:{account}:database/{db_name}"
    role_arn = f"arn:aws:iam::{account}:role/sim2real-behav-integ-role"

    created = glue.create_integration_resource_property(
        ResourceArn=resource_arn,
        TargetProcessingProperties={"RoleArn": role_arn},
    )
    ctx.on_cleanup(lambda: _cleanup_resource_property(glue, resource_arn))
    assert created["ResourceArn"] == resource_arn, (
        f"create echoed ResourceArn={created.get('ResourceArn')!r}, expected {resource_arn!r}"
    )
    assert created["ResourcePropertyArn"].endswith(f"integrationresourceproperty/database/{db_name}"), (
        f"create returned ResourcePropertyArn={created.get('ResourcePropertyArn')!r}, "
        f"expected it to end with integrationresourceproperty/database/{db_name}"
    )

    got = glue.get_integration_resource_property(ResourceArn=resource_arn)
    assert got["ResourceArn"] == resource_arn, (
        f"get ResourceArn={got.get('ResourceArn')!r}, expected {resource_arn!r}"
    )
    assert got["TargetProcessingProperties"]["RoleArn"] == role_arn, (
        f"get TargetProcessingProperties.RoleArn={got['TargetProcessingProperties'].get('RoleArn')!r}, "
        f"expected {role_arn!r}"
    )

    glue.delete_integration_resource_property(ResourceArn=resource_arn)

    code, message = _error(lambda: glue.get_integration_resource_property(ResourceArn=resource_arn))
    assert code == "EntityNotFoundException", (
        f"get after delete returned code={code!r}, expected EntityNotFoundException"
    )
    expected = f"The target resource {resource_arn} is not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The delete must also make the id unusable, not merely absent from a read.
    redelete_code, redelete_message = _error(lambda: glue.delete_integration_resource_property(ResourceArn=resource_arn))
    assert redelete_code == "EntityNotFoundException", (
        f"delete of an already-deleted resource property returned code={redelete_code!r}, "
        f"expected EntityNotFoundException"
    )
    expected = f"The target resource {resource_arn} is not found."
    assert redelete_message == expected, f"expected message {expected!r}, got {redelete_message!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; raise if it
    succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, call succeeded instead with {result!r}")


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_database(ctx, glue) -> str:
    db_name = ctx.unique_name("sim2real_behav_integres_db_")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: _cleanup_database(glue, db_name))
    return db_name


def _cleanup_resource_property(glue, resource_arn: str) -> None:
    try:
        glue.delete_integration_resource_property(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "EntityNotFoundException",
            "ResourceNotFoundException",
        ):
            raise


def _cleanup_database(glue, db_name: str) -> None:
    try:
        glue.delete_database(Name=db_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
