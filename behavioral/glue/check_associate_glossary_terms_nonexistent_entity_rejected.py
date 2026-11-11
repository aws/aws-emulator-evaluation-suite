"""associate-glossary-terms-nonexistent-entity-rejected."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-glossary-terms-nonexistent-entity-rejected"
GROUP = "negative-classes"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateGlossaryTerms against a nonexistent asset id raises EntityNotFoundException, while
    the same term associates with a real asset and GetAsset shows the association.

    Reference: https://docs.aws.amazon.com/glue/latest/dg/aws-glue-api-catalog-aws-glue-api-semantics.html
    """
    glue = ctx.client("glue")
    if not hasattr(glue, "associate_glossary_terms") or not hasattr(glue, "put_asset"):
        raise AssertionError(
            "installed botocore has no associate_glossary_terms/put_asset "
            "operation (AWS Glue Data Catalog business glossaries API is "
            "newer than this SDK build)"
        )

    glossary_name = ctx.unique_name("sim2real-glossary-")
    glossary_id = glue.create_glossary(Name=glossary_name)["Id"]
    ctx.on_cleanup(lambda: glue.delete_glossary(Identifier=glossary_id))

    term_name = ctx.unique_name("sim2real-term-")
    term_id = glue.create_glossary_term(GlossaryIdentifier=glossary_id, Name=term_name)["Id"]
    ctx.on_cleanup(lambda: glue.delete_glossary_term(Identifier=term_id))

    suffix = uuid.uuid4().hex[:10]
    form_type_name = f"Sim2RealBehavForm{suffix}"
    asset_type_name = f"Sim2RealBehavAsset{suffix}"

    # A Data Catalog table does not reliably resolve as an Asset, so build one directly through
    # PutFormType -> PutAssetType -> PutAsset.
    glue.put_form_type(
        Name=form_type_name,
        Schema=f"structure {form_type_name} {{\n    note: String\n}}",
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: glue.delete_form_type(Identifier=form_type_name)))

    glue.put_asset_type(
        Name=asset_type_name,
        Forms={form_type_name: {"FormTypeIdentifier": form_type_name}},
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: glue.delete_asset_type(Identifier=asset_type_name)))

    asset_id = ctx.unique_name("sim2real-asset-")
    glue.put_asset(
        AssetTypeId=asset_type_name,
        Identifier=asset_id,
        Name=asset_id,
        Forms={
            form_type_name: {
                "FormTypeId": form_type_name,
                "Content": json.dumps({"note": "sim2real behavioral asset"}),
            }
        },
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: glue.delete_asset(Identifier=asset_id)))

    bogus_asset_id = ctx.unique_name("sim2real-asset-missing-")

    code, message = _error(
        lambda: glue.associate_glossary_terms(
            AssetIdentifier=bogus_asset_id,
            GlossaryTermIdentifiers=[term_id],
        )
    )
    assert code == "EntityNotFoundException", (
        f"expected EntityNotFoundException for a nonexistent asset id, got {code!r}"
    )
    expected_message = f'{{"Message":"Asset not found: {bogus_asset_id}"}}'
    assert message == expected_message, (
        f"expected AssociateGlossaryTerms' not-found message {expected_message!r}, got {message!r}"
    )

    # Effect absent: the bogus asset id acquired no glossary-term
    # association (there is nothing to fetch it from -- it never became a
    # real asset).
    absent_code, absent_message = _error(lambda: glue.get_asset(Identifier=bogus_asset_id))
    assert absent_code == "EntityNotFoundException", (
        f"expected GetAsset on the never-created asset id to also raise "
        f"EntityNotFoundException, got {absent_code!r}"
    )
    expected_absent = f'{{"Message":"Asset not found: {bogus_asset_id}"}}'
    assert absent_message == expected_absent, (
        f"expected GetAsset's not-found message {expected_absent!r}, got {absent_message!r}"
    )

    # Positive control: the same term associated with the real asset succeeds.
    resp = glue.associate_glossary_terms(
        AssetIdentifier=asset_id,
        GlossaryTermIdentifiers=[term_id],
    )
    assert term_id in resp["GlossaryTerms"], (
        f"expected {term_id!r} in the AssociateGlossaryTerms response, "
        f"got {resp.get('GlossaryTerms')!r}"
    )

    # Terminal read independent of the mutating call: GetAsset, not
    # AssociateGlossaryTerms's own response, confirms the association
    # actually landed on the asset at the destination.
    asset_after = glue.get_asset(Identifier=asset_id)
    assert term_id in asset_after["GlossaryTerms"], (
        f"expected {term_id!r} in GetAsset's GlossaryTerms for {asset_id!r}, "
        f"got {asset_after.get('GlossaryTerms')!r}"
    )


def _error(fn) -> tuple[str, str]:
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, call unexpectedly succeeded with: {resp!r}")


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
