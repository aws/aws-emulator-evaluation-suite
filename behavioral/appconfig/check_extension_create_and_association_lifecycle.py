"""extension-create-and-association-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "extension-create-and-association-lifecycle"
GROUP = 'extension'
SERVICES = ['appconfig']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-extension-create-and-association-lifecycle"}


def _client_error(fn):
    """Call fn(); return its Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, call succeeded and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Extension association links an extension to an application and is independently deletable."""
    ac = ctx.client("appconfig")
    account = ctx.client("sts").get_caller_identity()["Account"]
    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: ac.delete_application(ApplicationId=app_id))
    account_arn = f"arn:aws:appconfig:{ctx.region}:{account}:application/{app_id}"

    # An extension's action ARNs must be built in the CALLING account (AppConfig rejects
    # a cross-account RoleArn); the referenced topic/role need not exist at create time.
    extension = ac.create_extension(
        Name=ctx.unique_name("sim2real-behav-ext-"),
        Actions={
            "ON_DEPLOYMENT_START": [
                {
                    "Name": ctx.unique_name("sim2real-behav-action-"),
                    "Uri": f"arn:aws:sns:{ctx.region}:{account}:{ctx.unique_name('sim2real-behav-topic-')}",
                    "RoleArn": f"arn:aws:iam::{account}:role/{ctx.unique_name('sim2real-behav-role-')}",
                }
            ]
        },
        Tags=_TAGS,
    )
    ext_id = extension["Id"]
    ctx.on_cleanup(lambda: ac.delete_extension(ExtensionIdentifier=ext_id))

    association = ac.create_extension_association(
        ExtensionIdentifier=extension["Id"], ResourceIdentifier=account_arn, Tags=_TAGS
    )
    assoc_id = association["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: ac.delete_extension_association(ExtensionAssociationId=assoc_id)))
    assert association["ExtensionArn"] == extension["Arn"], (
        f"expected association ExtensionArn {extension['Arn']!r}, got {association['ExtensionArn']!r}"
    )

    got = ac.get_extension_association(ExtensionAssociationId=association["Id"])
    assert got["ResourceArn"] == account_arn, (
        f"expected ResourceArn {account_arn!r}, got {got['ResourceArn']!r}"
    )

    ac.delete_extension_association(ExtensionAssociationId=association["Id"])

    not_found = f"ExtensionAssociation could not be found for account {account}."
    err = _client_error(lambda: ac.get_extension_association(ExtensionAssociationId=association["Id"]))
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {err['Code']}"
    assert err["Message"] == not_found, f"expected message {not_found!r}, got {err['Message']!r}"

    # A mutation on the deleted id must fail too, not just a read.
    redelete_err = _client_error(
        lambda: ac.delete_extension_association(ExtensionAssociationId=association["Id"])
    )
    assert redelete_err["Code"] == "ResourceNotFoundException", (
        f"expected second delete on dead association to 404, got {redelete_err['Code']}"
    )
    assert redelete_err["Message"] == not_found, f"expected message {not_found!r}, got {redelete_err['Message']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
