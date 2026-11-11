"""op-contract-deleteExtensionAssociation."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteExtensionAssociation"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-delete-extension-association-rejected"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteExtensionAssociation removes the association (positive control); a second
    delete on the now-absent association is rejected with ResourceNotFoundException and
    the association stays absent from GetExtensionAssociation / ListExtensionAssociations."""
    appconfig = ctx.client("appconfig")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    app_arn = f"arn:aws:appconfig:{ctx.region}:{account_id}:application/{app_id}"

    # AWS rejects an Extension Action with a null/blank URI, so every action must
    # reference some target; the action is never actually invoked in this check (no
    # deployment is started), so a syntactically valid ARN that AppConfig never needs
    # to call is sufficient.
    extension_id = appconfig.create_extension(
        Name=ctx.unique_name("sim2real-ext-"),
        Actions={
            "ON_DEPLOYMENT_COMPLETE": [
                {
                    "Name": "noop-action",
                    "Uri": f"arn:aws:sns:{ctx.region}:{account_id}:sim2real-noop-topic",
                }
            ]
        },
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_extension(ExtensionIdentifier=extension_id))

    assoc = appconfig.create_extension_association(
        ExtensionIdentifier=extension_id, ResourceIdentifier=app_arn
    )
    assoc_id = assoc["Id"]

    # positive control: association is readable before deletion
    appconfig.get_extension_association(ExtensionAssociationId=assoc_id)
    before = appconfig.list_extension_associations()["Items"]
    assert any(a["Id"] == assoc_id for a in before), f"expected {assoc_id} in list before delete"

    appconfig.delete_extension_association(ExtensionAssociationId=assoc_id)

    not_found = f"ExtensionAssociation could not be found for account {account_id}."
    code, message = _client_error(
        lambda: appconfig.get_extension_association(ExtensionAssociationId=assoc_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException on Get, got {code}"
    assert message == not_found, f"expected {not_found!r} on Get, got {message!r}"
    after = appconfig.list_extension_associations()["Items"]
    assert all(a["Id"] != assoc_id for a in after), f"expected {assoc_id} absent from list after delete"

    # negative: deleting the already-deleted association is rejected, effect stays absent
    code, message = _client_error(
        lambda: appconfig.delete_extension_association(ExtensionAssociationId=assoc_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == not_found, f"expected {not_found!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return (code, message) of its botocore ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
