"""asset-lifecycle-put-get-delete."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asset-lifecycle-put-get-delete"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAsset creates/updates an asset, GetAsset reflects its content, DeleteAsset removes it
    and GetAsset then raises EntityNotFoundException."""
    glue = ctx.client("glue")

    form_name = _alnum_id("SimBehavAssetForm")
    schema = f"structure {form_name} {{\n    owner: String\n}}"
    glue.put_form_type(Name=form_name, Schema=schema)
    ctx.on_cleanup(lambda: _cleanup_form_type(glue, form_name))

    asset_type_name = _alnum_id("SimBehavAssetType")
    glue.put_asset_type(Name=asset_type_name, Forms={form_name: {"FormTypeIdentifier": form_name}})
    ctx.on_cleanup(lambda: _cleanup_asset_type(glue, asset_type_name))

    asset_id = ctx.unique_name("sim2real-behav-asset-")
    content = json.dumps({"owner": "sim2real-team"})

    created = glue.put_asset(
        AssetTypeId=asset_type_name,
        Identifier=asset_id,
        Name="Sim2Real Behavioral Asset",
        Description="behavioral fidelity check asset",
        Forms={form_name: {"FormTypeId": form_name, "Content": content}},
    )
    ctx.on_cleanup(lambda: _cleanup_asset(glue, asset_id))
    assert created["Id"] == asset_id, f"expected PutAsset to echo Id={asset_id!r}, got {created['Id']!r}"

    got = glue.get_asset(Identifier=asset_id)
    assert got["Name"] == "Sim2Real Behavioral Asset", (
        f"expected GetAsset Name='Sim2Real Behavioral Asset', got {got['Name']!r}"
    )
    assert got["AssetTypeId"] == asset_type_name, (
        f"expected GetAsset AssetTypeId={asset_type_name!r}, got {got['AssetTypeId']!r}"
    )
    # compare parsed JSON (the service may re-serialize whitespace/ordering differently)
    got_content = json.loads(got["Forms"][form_name]["Content"])
    want_content = json.loads(content)
    assert got_content == want_content, f"expected form content {want_content!r}, got {got_content!r}"

    glue.delete_asset(Identifier=asset_id)

    code, message = _error(lambda: glue.get_asset(Identifier=asset_id))
    assert code == "EntityNotFoundException", (
        f"expected GetAsset on a deleted asset to raise EntityNotFoundException, got {code!r}"
    )
    expected_message = f'{{"Message":"Asset not found: {asset_id}"}}'
    assert message == expected_message, (
        f"expected GetAsset's not-found message {expected_message!r}, got {message!r}"
    )


# ===== helpers =====
def _alnum_id(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex[:10]}"


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _cleanup_form_type(glue, identifier: str) -> None:
    try:
        glue.delete_form_type(Identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _cleanup_asset_type(glue, identifier: str) -> None:
    try:
        glue.delete_asset_type(Identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _cleanup_asset(glue, identifier: str) -> None:
    try:
        glue.delete_asset(Identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
