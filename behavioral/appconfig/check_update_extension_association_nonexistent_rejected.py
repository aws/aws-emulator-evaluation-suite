"""update-extension-association-nonexistent-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-extension-association-nonexistent-rejected"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-update-extassoc-nonexistent"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateExtensionAssociation on an association id that does not exist returns
    ResourceNotFoundException and leaves the real association untouched, while updating
    the real association id succeeds."""
    appconfig = ctx.client("appconfig")
    sqs = ctx.client("sqs")

    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-extq-"), tags=_TAGS)[
        "QueueUrl"
    ]
    ctx.on_cleanup(lambda: _safe_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url)))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    extension = appconfig.create_extension(
        Name=ctx.unique_name("sim2real-behav-ext-"),
        Actions={"ON_DEPLOYMENT_COMPLETE": [{"Name": "notify", "Uri": queue_arn}]},
        Tags=_TAGS,
    )
    extension_id = extension["Id"]
    ctx.on_cleanup(
        lambda: _safe_cleanup(lambda: appconfig.delete_extension(ExtensionIdentifier=extension_id))
    )

    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)[
        "Id"
    ]
    ctx.on_cleanup(
        lambda: _safe_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    )
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    app_arn = f"arn:aws:appconfig:{ctx.region}:{account_id}:application/{app_id}"

    association = appconfig.create_extension_association(
        ExtensionIdentifier=extension_id, ResourceIdentifier=app_arn, Tags=_TAGS
    )
    association_id = association["Id"]
    ctx.on_cleanup(
        lambda: _safe_cleanup(
            lambda: appconfig.delete_extension_association(ExtensionAssociationId=association_id)
        )
    )

    # same-length, same-charset ([a-z0-9]{4,7}) id so it clears the ExtensionAssociationId
    # pattern validation, but reversed so it does not match the real association
    bogus_id = association_id[::-1]
    assert bogus_id != association_id, (
        f"test setup broken: bogus id {bogus_id!r} collides with real id {association_id!r}"
    )
    code, message = _error(
        lambda: appconfig.update_extension_association(
            ExtensionAssociationId=bogus_id,
            Parameters={},
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for nonexistent association {bogus_id!r}, got {code!r}"
    )
    expected = f"ExtensionAssociation could not be found for account {ctx.account}."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: exactly one association exists and it is unchanged
    listing = appconfig.list_extension_associations()
    matches = [item for item in listing["Items"] if item["Id"] == association_id]
    assert len(matches) == 1, (
        f"expected exactly 1 association with id {association_id!r} after the rejected "
        f"bogus-id update, found {len(matches)}"
    )

    # positive control: updating the real association id succeeds
    updated = appconfig.update_extension_association(
        ExtensionAssociationId=association_id, Parameters={}
    )
    assert updated["Id"] == association_id, (
        f"expected update response Id {association_id!r}, got {updated['Id']!r}"
    )
    assert updated["ResourceArn"] == app_arn, (
        f"expected update response ResourceArn {app_arn!r}, got {updated['ResourceArn']!r}"
    )

    # terminal read is independent of the mutating call: a fresh Get must agree, not just
    # the UpdateExtensionAssociation response itself.
    refreshed = appconfig.get_extension_association(ExtensionAssociationId=association_id)
    assert refreshed["Id"] == association_id, (
        f"expected a fresh GetExtensionAssociation to report Id {association_id!r}, "
        f"got {refreshed['Id']!r}"
    )
    assert refreshed["ResourceArn"] == app_arn, (
        f"expected a fresh GetExtensionAssociation to report ResourceArn {app_arn!r}, "
        f"got {refreshed['ResourceArn']!r}"
    )
    assert refreshed["ExtensionArn"] == extension["Arn"], (
        f"expected the update to leave the association bound to {extension['Arn']!r}, "
        f"got {refreshed['ExtensionArn']!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected a ClientError, but the call succeeded and returned {result!r}"
    )


def _safe_cleanup(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
