"""list-extension-associations-filtered-by-resource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-extension-associations-filtered-by-resource"
GROUP = "data-plane"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListExtensionAssociations, filtered by resource ARN, returns only associations for that resource."""
    appconfig = ctx.client("appconfig")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    resource_tags = {
        "sim2real:managed": "true",
        "sim2real": "appconfig-list-extension-associations-filtered-by-resource",
    }

    app_a = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-appa-"), Tags=resource_tags)
    app_a_id = app_a["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_a_id))
    arn_a = f"arn:aws:appconfig:{ctx.region}:{account_id}:application/{app_a_id}"

    app_b = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-appb-"), Tags=resource_tags)
    app_b_id = app_b["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_b_id))
    arn_b = f"arn:aws:appconfig:{ctx.region}:{account_id}:application/{app_b_id}"

    ext_a = appconfig.create_extension(
        Name=ctx.unique_name("sim2real-behav-exta-"),
        Actions={
            "ON_DEPLOYMENT_COMPLETE": [
                {"Name": "notify", "Uri": f"arn:aws:sns:{ctx.region}:{account_id}:sim2real-behav-topic-a"}
            ]
        },
        Tags=resource_tags,
    )
    ext_a_id = ext_a["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_extension(ExtensionIdentifier=ext_a_id))

    ext_b = appconfig.create_extension(
        Name=ctx.unique_name("sim2real-behav-extb-"),
        Actions={
            "ON_DEPLOYMENT_COMPLETE": [
                {"Name": "notify", "Uri": f"arn:aws:sns:{ctx.region}:{account_id}:sim2real-behav-topic-b"}
            ]
        },
        Tags=resource_tags,
    )

    ext_b_id = ext_b["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_extension(ExtensionIdentifier=ext_b_id))

    assoc_a = appconfig.create_extension_association(
        ExtensionIdentifier=ext_a_id, ResourceIdentifier=arn_a, Tags=resource_tags
    )
    assoc_a_id = assoc_a["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_extension_association(ExtensionAssociationId=assoc_a_id))

    assoc_b = appconfig.create_extension_association(
        ExtensionIdentifier=ext_b_id, ResourceIdentifier=arn_b, Tags=resource_tags
    )
    assoc_b_id = assoc_b["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_extension_association(ExtensionAssociationId=assoc_b_id))

    filtered = appconfig.list_extension_associations(ResourceIdentifier=arn_a)["Items"]
    filtered_ids = [item["Id"] for item in filtered]

    assert assoc_a_id in filtered_ids, (
        f"expected association {assoc_a_id} for resource {arn_a} in filtered list, got ids {filtered_ids}"
    )
    assert assoc_b_id not in filtered_ids, (
        f"association {assoc_b_id} for a different resource ({arn_b}) leaked into the "
        f"ResourceIdentifier={arn_a} filtered list: {filtered_ids}"
    )
    for item in filtered:
        assert item["ResourceArn"] == arn_a, (
            f"filtered list for ResourceIdentifier={arn_a} returned an item for {item['ResourceArn']}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
