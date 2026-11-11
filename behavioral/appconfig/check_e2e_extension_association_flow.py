"""e2e-extension-association-flow."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "e2e-extension-association-flow"
GROUP = "e2e"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An extension association's updated Parameters show in Get and List, and after both deletes
    Get on the association and on the extension raise ResourceNotFoundException with AWS's exact
    messages, so the lifecycle is observed rather than inferred from call success.
    """
    appconfig = ctx.client("appconfig")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    tags = {"sim2real:managed": "true", "sim2real": "appconfig-e2e-extension-association-flow"}

    application = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=tags)
    app_id = application["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    resource_arn = f"arn:aws:appconfig:{ctx.region}:{account_id}:application/{app_id}"

    fake_sns_arn = f"arn:aws:sns:{ctx.region}:{account_id}:sim2real-behav-notify-topic"
    extension = appconfig.create_extension(
        Name=ctx.unique_name("sim2real-behav-ext-"),
        Actions={"ON_DEPLOYMENT_COMPLETE": [{"Name": "notify", "Uri": fake_sns_arn}]},
        Parameters={"greeting": {"Description": "a greeting", "Required": False}},
        Tags=tags,
    )
    extension_id = extension["Id"]

    association = appconfig.create_extension_association(
        ExtensionIdentifier=extension_id,
        ResourceIdentifier=resource_arn,
        Parameters={"greeting": "hello"},
        Tags=tags,
    )
    association_id = association["Id"]
    assert association["Parameters"]["greeting"] == "hello", (
        f"expected CreateExtensionAssociation to echo Parameters={{'greeting': 'hello'}}, "
        f"got {association['Parameters']!r}"
    )

    appconfig.update_extension_association(
        ExtensionAssociationId=association_id, Parameters={"greeting": "world"}
    )

    listed = appconfig.list_extension_associations(ResourceIdentifier=resource_arn)["Items"]
    matching = [item for item in listed if item["Id"] == association_id]
    assert len(matching) == 1, (
        f"expected exactly one ListExtensionAssociations entry for {association_id}, "
        f"found {len(matching)} in {[item['Id'] for item in listed]!r}"
    )
    assert matching[0]["ExtensionArn"] == extension["Arn"], (
        f"expected listed ExtensionArn {extension['Arn']!r}, got {matching[0]['ExtensionArn']!r}"
    )

    fetched = appconfig.get_extension_association(ExtensionAssociationId=association_id)
    assert fetched["Parameters"]["greeting"] == "world", (
        f"expected GetExtensionAssociation to reflect the update to 'world', "
        f"got {fetched['Parameters']!r}"
    )

    appconfig.delete_extension_association(ExtensionAssociationId=association_id)
    appconfig.delete_extension(ExtensionIdentifier=extension_id)

    remaining = appconfig.list_extension_associations(ResourceIdentifier=resource_arn)["Items"]
    assert association_id not in [item["Id"] for item in remaining], (
        f"deleted association {association_id} still present in ListExtensionAssociations: {remaining!r}"
    )

    code_assoc, message_assoc = _client_error(
        lambda: appconfig.get_extension_association(ExtensionAssociationId=association_id)
    )
    assert code_assoc == "ResourceNotFoundException", (
        f"expected GetExtensionAssociation on a deleted association to raise ResourceNotFoundException, "
        f"got {code_assoc!r}"
    )
    expected_assoc = f"ExtensionAssociation could not be found for account {account_id}."
    assert message_assoc == expected_assoc, f"expected {expected_assoc!r}, got {message_assoc!r}"

    code_ext, message_ext = _client_error(
        lambda: appconfig.get_extension(ExtensionIdentifier=extension_id)
    )
    assert code_ext == "ResourceNotFoundException", (
        f"expected GetExtension on a deleted extension to raise ResourceNotFoundException, got {code_ext!r}"
    )
    expected_ext = f"Extension could not be found for account {account_id}."
    assert message_ext == expected_ext, f"expected {expected_ext!r}, got {message_ext!r}"


def _client_error(fn):
    """Call fn(); return (code, message) of its botocore ClientError. An unexpected SUCCESS
    raises, because a target ACCEPTING a call real AWS refuses must not be reported as an
    error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
