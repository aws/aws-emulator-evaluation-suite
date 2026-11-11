"""form-type-delete-referenced-by-asset-type-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "form-type-delete-referenced-by-asset-type-rejected"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAssetType naming a missing form type is rejected with EntityNotFoundException and creates
    nothing; DeleteFormType on a form type an asset type still references is rejected with
    ConflictException, and succeeds once that asset type is deleted."""
    glue = ctx.client("glue")
    asset_type_name = _alnum_id("SimBehavRefAssetType")
    bogus_form_id = _alnum_id("SimBehavMissingForm")

    code, message = _error(
        lambda: glue.put_asset_type(
            Name=asset_type_name, Forms={bogus_form_id: {"FormTypeIdentifier": bogus_form_id}}
        )
    )
    assert code == "EntityNotFoundException", f"unexpected error code: {code}"
    expected = f'{{"Message":"Metadata form type {bogus_form_id} not found."}}'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: no asset type was created by the rejected call
    not_found_code, not_found_message = _error(
        lambda: glue.get_asset_type(Identifier=asset_type_name)
    )
    assert not_found_code == "EntityNotFoundException", (
        f"expected the rejected PutAssetType to leave no asset type behind, got code "
        f"{not_found_code!r}"
    )
    expected = f'{{"Message":"Asset type {asset_type_name} not found."}}'
    assert not_found_message == expected, f"expected message {expected!r}, got {not_found_message!r}"

    # positive control: once the referenced form type actually exists, the identical shape succeeds
    form_name = _alnum_id("SimBehavRefForm")
    schema = f"structure {form_name} {{\n    label: String\n}}"
    glue.put_form_type(Name=form_name, Schema=schema)
    ctx.on_cleanup(lambda: _cleanup_form_type(glue, form_name))

    glue.put_asset_type(Name=asset_type_name, Forms={form_name: {"FormTypeIdentifier": form_name}})
    ctx.on_cleanup(lambda: _cleanup_asset_type(glue, asset_type_name))
    got = glue.get_asset_type(Identifier=asset_type_name)
    assert form_name in got["Forms"], (
        f"expected asset type {asset_type_name!r} to list {form_name!r} as a referenced form, "
        f"got {list(got['Forms'])!r}"
    )

    # the reference index backing this guard is eventually consistent: poll for the conflict
    # to actually be enforced instead of asserting on the first (possibly too-early) attempt
    conflict_code, conflict_message = _poll_for_conflict(glue, form_name)
    assert conflict_code == "ConflictException", f"unexpected error code: {conflict_code}"
    expected = (
        f'{{"Message":"Form type {form_name} cannot be deleted because of the following '
        f'dependencies: gluetype glueAsset#glue_{ctx.account}#{asset_type_name}"}}'
    )
    assert conflict_message == expected, f"expected message {expected!r}, got {conflict_message!r}"

    # effect absent: the form type is still there, unaffected by the rejected delete
    got_after_reject = glue.get_form_type(Identifier=form_name)
    assert got_after_reject["Id"] == form_name, (
        f"expected the still-referenced form type {form_name!r} to survive the rejected delete "
        f"intact, got Id {got_after_reject.get('Id')!r}"
    )

    # positive control: after removing the referencing asset type, the identical delete succeeds
    glue.delete_asset_type(Identifier=asset_type_name)
    glue.delete_form_type(Identifier=form_name)

    code_after, message_after = _error(lambda: glue.get_form_type(Identifier=form_name))
    assert code_after == "EntityNotFoundException", (
        f"expected the form type to be gone once the referencing asset type was removed, got "
        f"code {code_after!r}"
    )
    expected = f'{{"Message":"Metadata form type {form_name} not found."}}'
    assert message_after == expected, f"expected message {expected!r}, got {message_after!r}"


# ===== helpers =====
def _alnum_id(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex[:10]}"


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected success raises, so a
    target accepting what AWS refuses fails as an acceptance, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError rejection, but the call SUCCEEDED: {result!r}")


def _poll_for_conflict(glue, form_name: str, attempts: int = 6, delay: float = 3.0):
    """Return (code, message) of the first refused delete; (None, "") if every attempt succeeded."""
    code, message = None, ""
    for i in range(attempts):
        try:
            glue.delete_form_type(Identifier=form_name)
            code, message = None, ""
        except ClientError as exc:
            code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
        if code == "ConflictException":
            return code, message
        if code is None:
            # the delete unexpectedly succeeded (reference index not yet propagated when we
            # first tried) -- recreate the form type and asset-type reference and try again
            glue.put_form_type(
                Name=form_name, Schema=f"structure {form_name} {{\n    label: String\n}}"
            )
        if i < attempts - 1:
            time.sleep(delay)
    return code, message


def _cleanup_form_type(glue, identifier: str) -> None:
    # The asset type's reference is released eventually: retry ConflictException briefly.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            glue.delete_form_type(Identifier=identifier)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "EntityNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _cleanup_asset_type(glue, identifier: str) -> None:
    try:
        glue.delete_asset_type(Identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


