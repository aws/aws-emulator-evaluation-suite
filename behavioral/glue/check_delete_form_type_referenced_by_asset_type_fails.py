"""delete-form-type-referenced-by-asset-type-fails."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-form-type-referenced-by-asset-type-fails"
GROUP = "overly-permissive"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """DeleteFormType on a form type referenced by an asset type raises ConflictException and leaves
    it intact; an unreferenced form type, or the same one once unreferenced, deletes and 404s."""
    glue = ctx.client("glue")

    form_ref_name = _pascal_name(ctx, "FormRef")
    form_ctrl_name = _pascal_name(ctx, "FormCtrl")
    asset_type_name = _pascal_name(ctx, "AssetType")
    form_ref_schema = f"structure {form_ref_name} {{\n    value: String\n}}"

    glue.put_form_type(Name=form_ref_name, Schema=form_ref_schema)
    ctx.on_cleanup(lambda: _safe_delete_form_type(glue, form_ref_name))

    glue.put_form_type(
        Name=form_ctrl_name,
        Schema=f"structure {form_ctrl_name} {{\n    value: String\n}}",
    )
    ctx.on_cleanup(lambda: _safe_delete_form_type(glue, form_ctrl_name))

    glue.put_asset_type(
        Name=asset_type_name,
        Forms={form_ref_name: {"FormTypeIdentifier": form_ref_name}},
    )
    ctx.on_cleanup(lambda: _safe_delete_asset_type(glue, asset_type_name))

    fetched_asset_type = glue.get_asset_type(Identifier=asset_type_name)
    assert form_ref_name in fetched_asset_type["Forms"], (
        f"asset type does not list {form_ref_name} as referenced form: "
        f"{fetched_asset_type['Forms']!r}"
    )

    asset_id = ctx.unique_name("sim2real-asset-").lower()
    glue.put_asset(
        AssetTypeId=asset_type_name,
        Identifier=asset_id,
        Name=asset_id,
        Forms={form_ref_name: {"FormTypeId": form_ref_name, "Content": "{}"}},
    )
    ctx.on_cleanup(lambda: _safe_delete_asset(glue, asset_id))

    # Positive control: an unreferenced form type deletes cleanly.
    glue.delete_form_type(Identifier=form_ctrl_name)
    control_absence = _refusal(lambda: glue.get_form_type(Identifier=form_ctrl_name))
    assert control_absence == (
        "EntityNotFoundException",
        f'{{"Message":"Metadata form type {form_ctrl_name} not found."}}',
    ), control_absence

    # Negative: form_ref_name is still referenced by asset_type_name. The reference-index
    # backing this guard is eventually consistent, so a delete issued too soon after the
    # reference is created can race ahead of the index and succeed; poll for the conflict
    # to actually be enforced, recreating the form type if a premature delete goes through.
    conflict_message = _conflict_message(form_ref_name, asset_type_name, ctx.account)
    conflict = _poll_for_conflict(glue, form_ref_name, form_ref_schema)
    assert conflict == ("ConflictException", conflict_message), (
        f"expected ConflictException, got {conflict!r}"
    )

    # Effect absent: the referenced form type must still exist, untouched.
    still_there = glue.get_form_type(Identifier=form_ref_name)
    assert still_there["Name"] == form_ref_name

    # Restore: once the referencing asset and asset type are removed, the identical
    # delete call succeeds -- the guard is a live reference check, not a permanent lock.
    glue.delete_asset(Identifier=asset_id)
    glue.delete_asset_type(Identifier=asset_type_name)
    _delete_form_type_once_unreferenced(glue, form_ref_name, conflict_message)
    restored_code = _refusal(lambda: glue.get_form_type(Identifier=form_ref_name))
    assert restored_code == (
        "EntityNotFoundException",
        f'{{"Message":"Metadata form type {form_ref_name} not found."}}',
    ), (
        f"expected EntityNotFoundException after restore, got {restored_code!r}"
    )



def _pascal_name(ctx: Any, label: str) -> str:
    raw = ctx.unique_name(f"{label}-")
    alnum = "".join(ch for ch in raw if ch.isalnum())
    return alnum[0].upper() + alnum[1:]


def _conflict_message(form_type_name: str, asset_type_name: str, account: str) -> str:
    """The exact DeleteFormType refusal while asset_type_name still references the form type."""
    return (
        f'{{"Message":"Form type {form_type_name} cannot be deleted because of the following '
        f'dependencies: gluetype glueAsset#glue_{account}#{asset_type_name}"}}'
    )


def _poll_for_conflict(
    glue: Any, form_ref_name: str, schema: str, attempts: int = 6, delay_s: float = 3.0
) -> tuple:
    """Retry DeleteFormType until the eventually consistent reference guard reports the conflict,
    recreating the form type after a premature success. Returns the last (code, message), or
    ("<succeeded>", "") when the last attempt was accepted."""
    outcome: tuple = ("<succeeded>", "")
    for attempt in range(attempts):
        try:
            glue.delete_form_type(Identifier=form_ref_name)
            outcome = ("<succeeded>", "")
            glue.put_form_type(Name=form_ref_name, Schema=schema)
        except ClientError as err:
            outcome = (err.response["Error"]["Code"], err.response["Error"].get("Message"))
            if outcome[0] == "ConflictException":
                return outcome
        if attempt < attempts - 1:
            time.sleep(delay_s)
    return outcome


def _delete_form_type_once_unreferenced(
    glue: Any, name: str, conflict_message: str, attempts: int = 6, delay_s: float = 3.0
) -> None:
    """Retry DeleteFormType for up to attempts*delay_s: the reference-index update from
    removing the asset type is itself asynchronous, so the guard can still see the stale
    reference for a few seconds after the referencing asset type is gone."""
    for attempt in range(attempts):
        try:
            glue.delete_form_type(Identifier=name)
            return
        except ClientError as err:
            refusal = (err.response["Error"]["Code"], err.response["Error"].get("Message"))
        if refusal != ("ConflictException", conflict_message) or attempt == attempts - 1:
            raise AssertionError(
                f"delete_form_type({name!r}) did not clear within "
                f"{attempts * delay_s}s of removing its last reference, got {refusal!r}"
            )
        time.sleep(delay_s)


def _refusal(fn: Any) -> tuple:
    """Return the (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete_form_type(glue: Any, name: str) -> None:
    """Delete the form type, retrying the conflict while a just-removed reference clears."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            glue.delete_form_type(Identifier=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "EntityNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _safe_delete_asset_type(glue: Any, name: str) -> None:
    try:
        glue.delete_asset_type(Identifier=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _safe_delete_asset(glue: Any, identifier: str) -> None:
    try:
        glue.delete_asset(Identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
