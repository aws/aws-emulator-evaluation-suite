"""extension-association-update-fields-and-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "extension-association-update-fields-and-not-found"
GROUP = "error-semantics"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateExtensionAssociation persists new Parameters (seen on a fresh Get) and raises
    ResourceNotFoundException for a nonexistent id; after a delete, Get and Update on the id raise
    it too.
    """
    appconfig = ctx.client("appconfig")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-appcfg-"))["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    app_arn = f"arn:aws:appconfig:{ctx.region}:{account_id}:application/{app_id}"

    fake_uri = f"arn:aws:sns:{ctx.region}:{account_id}:{ctx.unique_name('sim2real-topic-')}"
    ext = appconfig.create_extension(
        Name=ctx.unique_name("sim2real-ext-"),
        Actions={"ON_DEPLOYMENT_START": [{"Name": "notify", "Uri": fake_uri}]},
        Parameters={"greeting": {"Description": "a greeting", "Required": False}},
    )
    ext_id = ext["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_extension(ExtensionIdentifier=ext_id))

    assoc = appconfig.create_extension_association(
        ExtensionIdentifier=ext_id, ResourceIdentifier=app_arn, Parameters={"greeting": "hello"}
    )
    assoc_id = assoc["Id"]
    ctx.on_cleanup(lambda: _delete_association(appconfig, assoc_id))
    assert assoc["Parameters"] == {"greeting": "hello"}, (
        f"CreateExtensionAssociation echoed Parameters={assoc['Parameters']!r}, expected "
        f"{{'greeting': 'hello'}}"
    )

    updated = appconfig.update_extension_association(
        ExtensionAssociationId=assoc_id, Parameters={"greeting": "goodbye"}
    )
    assert updated["Parameters"] == {"greeting": "goodbye"}, (
        f"UpdateExtensionAssociation echoed Parameters={updated['Parameters']!r}, expected "
        f"{{'greeting': 'goodbye'}}"
    )

    # Persisted, not merely echoed.
    got = appconfig.get_extension_association(ExtensionAssociationId=assoc_id)
    assert got["Parameters"] == {"greeting": "goodbye"}, (
        f"a fresh GetExtensionAssociation read back Parameters={got['Parameters']!r}, expected "
        f"the persisted {{'greeting': 'goodbye'}}"
    )

    not_found = f"ExtensionAssociation could not be found for account {account_id}."
    err = _client_error(
        lambda: appconfig.update_extension_association(
            ExtensionAssociationId="zzzzzzz", Parameters={"greeting": "nope"}
        )
    )
    assert err["Code"] == "ResourceNotFoundException", (
        f"UpdateExtensionAssociation on a well-formed but nonexistent id returned {err['Code']!r}, "
        f"expected ResourceNotFoundException"
    )
    assert err["Message"] == not_found, f"expected message {not_found!r}, got {err['Message']!r}"

    # A delete genuinely removes the association: an independent read and a follow-on mutation
    # against the same id both refuse with the same specific not-found code.
    appconfig.delete_extension_association(ExtensionAssociationId=assoc_id)
    gone_err = _client_error(
        lambda: appconfig.get_extension_association(ExtensionAssociationId=assoc_id)
    )
    assert gone_err["Code"] == "ResourceNotFoundException", (
        f"GetExtensionAssociation on a deleted association returned {gone_err['Code']!r}, expected "
        f"ResourceNotFoundException"
    )
    assert gone_err["Message"] == not_found, f"expected message {not_found!r}, got {gone_err['Message']!r}"
    dead_update_err = _client_error(
        lambda: appconfig.update_extension_association(
            ExtensionAssociationId=assoc_id, Parameters={"greeting": "still-gone"}
        )
    )
    assert dead_update_err["Code"] == "ResourceNotFoundException", (
        f"UpdateExtensionAssociation on a deleted association returned {dead_update_err['Code']!r}, "
        f"expected ResourceNotFoundException"
    )
    assert dead_update_err["Message"] == not_found, (
        f"expected message {not_found!r}, got {dead_update_err['Message']!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict if a ClientError is raised. An unexpected SUCCESS
    raises, because an over-permissive target accepting a call real AWS refuses must not be reported
    as an error-code mismatch.
    """
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_association(appconfig, assoc_id):
    try:
        appconfig.delete_extension_association(ExtensionAssociationId=assoc_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
