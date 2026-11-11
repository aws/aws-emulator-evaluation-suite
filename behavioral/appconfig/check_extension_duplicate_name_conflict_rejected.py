"""extension-duplicate-name-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "extension-duplicate-name-conflict-rejected"
GROUP = 'overly-permissive'
SERVICES = ['appconfig']


def _client_error(fn):
    """Call fn() and return its ClientError's Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _extension_action(ctx, account):
    return {
        "ON_DEPLOYMENT_START": [
            {
                "Name": ctx.unique_name("sim2real-behav-action-"),
                "Uri": f"arn:aws:sns:{ctx.region}:{account}:{ctx.unique_name('sim2real-behav-topic-')}",
                "RoleArn": f"arn:aws:iam::{account}:role/{ctx.unique_name('sim2real-behav-role-')}",
            }
        ]
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateExtension reusing an in-use name raises BadRequestException (not the modeled
    ConflictException) and creates no duplicate; once the original is deleted the identical call
    succeeds.
    """
    ac = ctx.client("appconfig")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-ext-")

    first = ac.create_extension(Name=name, Actions=_extension_action(ctx, account))
    first_id = first["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: ac.delete_extension(ExtensionIdentifier=first_id)))
    assert first["Name"] == name, f"positive control: expected Name {name!r}, got {first['Name']!r}"

    err = _client_error(
        lambda: ac.create_extension(Name=name, Actions=_extension_action(ctx, account))
    )
    assert err["Code"] == "BadRequestException", f"expected BadRequestException, got {err['Code']}"
    duplicate = f"LatestVersionNumber not populated and an extension with name {name} already exists."
    assert err["Message"] == duplicate, f"expected message {duplicate!r}, got {err['Message']!r}"

    # Effect absent: the original extension is untouched, and no second extension
    # with the same name exists.
    still_there = ac.get_extension(ExtensionIdentifier=first_id)
    assert still_there["Name"] == name
    listing = ac.list_extensions(Name=name)["Items"]
    assert [item["Id"] for item in listing] == [first_id], (
        f"expected exactly one extension named {name!r}, got {listing}"
    )

    # Restore: once the name is freed, the identical call must succeed.
    ac.delete_extension(ExtensionIdentifier=first_id)
    not_found_err = _client_error(lambda: ac.get_extension(ExtensionIdentifier=first_id))
    assert not_found_err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {not_found_err['Code']}"
    )
    not_found = f"Extension could not be found for account {account}."
    assert not_found_err["Message"] == not_found, (
        f"expected message {not_found!r}, got {not_found_err['Message']!r}"
    )

    freed = ac.create_extension(Name=name, Actions=_extension_action(ctx, account))
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: ac.delete_extension(ExtensionIdentifier=freed["Id"])))
    assert freed["Name"] == name, f"expected the freed name to be reusable, got {freed['Name']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
