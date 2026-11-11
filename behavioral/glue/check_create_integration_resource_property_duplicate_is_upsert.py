"""create-integration-resource-property-duplicate-is-upsert."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-integration-resource-property-duplicate-is-upsert"
GROUP = "error-semantics"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second CreateIntegrationResourceProperty for the same resource ARN is an upsert: it does
    not raise a conflict error, and its TargetProcessingProperties replace the first call's."""
    glue = ctx.client("glue")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    db_name = ctx.unique_name("sim2real_glue_intprop_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _safe_delete_database(ctx, db_name))
    resource_arn = f"arn:aws:glue:{ctx.region}:{account_id}:database/{db_name}"

    conn1 = ctx.unique_name("sim2real-conn-")[:128]
    target_props = {
        "ConnectionName": conn1,
        "RoleArn": f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-role-')}",
    }
    glue.create_integration_resource_property(
        ResourceArn=resource_arn, TargetProcessingProperties=target_props
    )
    ctx.on_cleanup(lambda: _safe_delete_integration_resource_property(ctx, resource_arn))

    first = glue.get_integration_resource_property(ResourceArn=resource_arn)
    assert first["TargetProcessingProperties"]["ConnectionName"] == conn1, (
        f"expected first ConnectionName {conn1!r}, got "
        f"{first['TargetProcessingProperties'].get('ConnectionName')!r}"
    )

    conn2 = ctx.unique_name("sim2real-conn2-")[:128]
    different_props = {
        "ConnectionName": conn2,
        "RoleArn": f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-role2-')}",
    }
    second = glue.create_integration_resource_property(
        ResourceArn=resource_arn, TargetProcessingProperties=different_props
    )
    assert second["ResourceArn"] == resource_arn, (
        f"expected the second create to return ResourceArn {resource_arn!r}, got {second.get('ResourceArn')!r}"
    )

    updated = glue.get_integration_resource_property(ResourceArn=resource_arn)
    assert updated["TargetProcessingProperties"]["ConnectionName"] == conn2, (
        f"expected upsert to overwrite ConnectionName to {conn2!r}, got "
        f"{updated['TargetProcessingProperties'].get('ConnectionName')!r}"
    )
    assert updated["ResourceArn"] == resource_arn, (
        f"expected ResourceArn {resource_arn!r}, got {updated.get('ResourceArn')!r}"
    )


# ===== helpers =====
def _safe_delete_integration_resource_property(ctx, resource_arn):
    try:
        ctx.client("glue").delete_integration_resource_property(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _safe_delete_database(ctx, db_name):
    try:
        ctx.client("glue").delete_database(Name=db_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

