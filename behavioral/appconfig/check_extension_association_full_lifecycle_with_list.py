"""extension-association-full-lifecycle-with-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "extension-association-full-lifecycle-with-list"
GROUP = "extension"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateExtensionAssociation's Parameters changes show in Get and List; after the delete the
    association leaves the list and Get raises the not-found error.
    """
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    app_arn = _app_arn(ctx, app_id)

    ext = appconfig.create_extension(
        Name=ctx.unique_name("sim2real-ext-"),
        Actions={"ON_DEPLOYMENT_COMPLETE": [
            {"Name": "notify", "Uri": f"arn:aws:sns:{ctx.region}:{_account_id(ctx)}:sim2real-appconfig-ext-notify"},
        ]},
        Parameters={"stage": {"Required": False}},
        Tags={"sim2real": CHECK},
    )
    ext_id, ext_arn = ext["Id"], ext["Arn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_extension(ExtensionIdentifier=ext_id)))

    created = appconfig.create_extension_association(
        ExtensionIdentifier=ext_id, ResourceIdentifier=app_arn, Parameters={"stage": "beta"},
        Tags={"sim2real": CHECK},
    )
    assoc_id = created["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: appconfig.delete_extension_association(ExtensionAssociationId=assoc_id)))
    assert created["Parameters"] == {"stage": "beta"}
    assert created["ExtensionArn"] == ext_arn
    assert created["ResourceArn"] == app_arn

    got = appconfig.get_extension_association(ExtensionAssociationId=assoc_id)
    assert got["Parameters"] == {"stage": "beta"}

    updated = appconfig.update_extension_association(ExtensionAssociationId=assoc_id, Parameters={"stage": "prod"})
    assert updated["Parameters"] == {"stage": "prod"}

    got2 = appconfig.get_extension_association(ExtensionAssociationId=assoc_id)
    assert got2["Parameters"] == {"stage": "prod"}, "update not reflected in Get"

    listing = appconfig.list_extension_associations(ExtensionIdentifier=ext_id)["Items"]
    assert any(item["Id"] == assoc_id for item in listing), "association missing from List after update"

    appconfig.delete_extension_association(ExtensionAssociationId=assoc_id)

    not_found = f"ExtensionAssociation could not be found for account {_account_id(ctx)}."
    err = _client_error(lambda: appconfig.get_extension_association(ExtensionAssociationId=assoc_id))
    assert err["Code"] == "ResourceNotFoundException", f"expected 404 after delete, got {err['Code']}"
    assert err["Message"] == not_found, f"expected message {not_found!r}, got {err['Message']!r}"

    listing_after = appconfig.list_extension_associations(ExtensionIdentifier=ext_id)["Items"]
    assert not any(item["Id"] == assoc_id for item in listing_after), "deleted association still listed"

    mutate_err = _client_error(lambda: appconfig.update_extension_association(
        ExtensionAssociationId=assoc_id, Parameters={"stage": "post-delete"}))
    assert mutate_err["Code"] == "ResourceNotFoundException", (
        f"expected update on deleted association id to 404, got {mutate_err['Code']}"
    )
    assert mutate_err["Message"] == not_found, f"expected message {not_found!r}, got {mutate_err['Message']!r}"


def _client_error(fn):
    """Call fn() and return its ClientError's Error dict; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _app_arn(ctx, app_id):
    return f"arn:aws:appconfig:{ctx.region}:{_account_id(ctx)}:application/{app_id}"


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(
        Name=ctx.unique_name("sim2real-app-"), Tags={"sim2real": CHECK},
    )["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_application(ApplicationId=app_id)))
    return app_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
