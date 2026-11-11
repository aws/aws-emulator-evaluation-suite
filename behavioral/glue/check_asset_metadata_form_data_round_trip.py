"""asset-metadata-form-data-round-trip."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asset-metadata-form-data-round-trip"
GROUP = "representation"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAsset returns the Name, Description, AssetTypeId and form content that PutAsset wrote, and after the
    delete GetAsset fails with EntityNotFoundException and its exact message.
    """
    glue = ctx.client("glue")

    suffix = uuid.uuid4().hex[:10]
    form_type_name = f"Sim2RealForm{suffix}"
    asset_type_name = f"Sim2RealAssetType{suffix}"

    schema = f"structure {form_type_name} {{ owner: String priority: Integer notes: String }}"
    form_type = glue.put_form_type(Name=form_type_name, Schema=schema)
    form_type_id = form_type["Id"]
    ctx.on_cleanup(lambda: glue.delete_form_type(Identifier=form_type_id))

    asset_type = glue.put_asset_type(
        Name=asset_type_name,
        Forms={"MainForm": {"FormTypeIdentifier": form_type_id}},
    )
    asset_type_id = asset_type["Id"]
    ctx.on_cleanup(lambda: glue.delete_asset_type(Identifier=asset_type_id))

    asset_id = ctx.unique_name("sim2real-asset-")
    asset_name = "Sim2Real Asset 資産 🏷️"
    asset_description = "Structured metadata asset used for sim2real fidelity testing."
    content = {"owner": "team-鈴木-café", "priority": 3, "notes": "unicode content: naïve ☑️"}

    glue.put_asset(
        AssetTypeId=asset_type_id,
        Identifier=asset_id,
        Name=asset_name,
        Description=asset_description,
        Forms={"MainForm": {"FormTypeId": form_type_id, "Content": json.dumps(content)}},
    )
    ctx.on_cleanup(lambda: _delete_asset_idempotent(glue, asset_id))

    fetched = glue.get_asset(Identifier=asset_id)
    assert fetched["Id"] == asset_id, f"expected Id={asset_id!r}, got {fetched['Id']!r}"
    assert fetched["Name"] == asset_name, f"expected Name={asset_name!r}, got {fetched['Name']!r}"
    assert fetched["Description"] == asset_description, (
        f"expected Description={asset_description!r}, got {fetched['Description']!r}"
    )
    assert fetched["AssetTypeId"] == asset_type_id, (
        f"expected AssetTypeId={asset_type_id!r}, got {fetched['AssetTypeId']!r}"
    )

    fetched_form = fetched["Forms"]["MainForm"]
    assert fetched_form["FormTypeId"] == form_type_id, (
        f"expected FormTypeId={form_type_id!r}, got {fetched_form['FormTypeId']!r}"
    )
    fetched_content = json.loads(fetched_form["Content"])
    assert fetched_content == content, f"expected Content={content!r}, got {fetched_content!r}"

    glue.delete_asset(Identifier=asset_id)
    code, message = _error(lambda: glue.get_asset(Identifier=asset_id))
    assert code == "EntityNotFoundException", (
        f"expected GetAsset on a deleted asset to raise EntityNotFoundException, got {code!r}"
    )
    expected_message = f'{{"Message":"Asset not found: {asset_id}"}}'
    assert message == expected_message, (
        f"expected GetAsset's not-found message {expected_message!r}, got {message!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return the AWS error (Code, Message) it raised. An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_asset_idempotent(glue, asset_id: str) -> None:
    try:
        glue.delete_asset(Identifier=asset_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
