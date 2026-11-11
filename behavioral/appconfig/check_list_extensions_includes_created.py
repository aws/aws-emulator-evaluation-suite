"""list-extensions-includes-created."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-extensions-includes-created"
GROUP = "data-plane"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListExtensions surfaces a newly created extension with matching identifying fields."""
    appconfig = ctx.client("appconfig")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-behav-ext-")
    ids_before = {item["Id"] for item in appconfig.list_extensions(Name=name)["Items"]}
    assert not ids_before, f"expected no extension named {name!r} before creation, found {ids_before}"

    extension = appconfig.create_extension(
        Name=name,
        Actions={
            "ON_DEPLOYMENT_COMPLETE": [
                {"Name": "notify", "Uri": f"arn:aws:sns:{ctx.region}:{account_id}:sim2real-behav-topic"}
            ]
        },
    )

    extension_id = extension["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_extension(ExtensionIdentifier=extension_id))

    listed = appconfig.list_extensions(Name=name)["Items"]
    matching = [item for item in listed if item["Id"] == extension_id]
    assert len(matching) == 1, (
        f"expected exactly 1 extension {extension_id!r} named {name!r} in ListExtensions, got {len(matching)}"
    )
    assert matching[0]["Name"] == name, f"expected Name={name!r}, got {matching[0]['Name']!r}"
    assert matching[0]["Arn"] == extension["Arn"], (
        f"expected Arn={extension['Arn']!r}, got {matching[0]['Arn']!r}"
    )
    assert matching[0]["VersionNumber"] == extension["VersionNumber"] == 1, (
        f"expected VersionNumber==1 on both create and list responses, got "
        f"create={extension['VersionNumber']!r} list={matching[0]['VersionNumber']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
