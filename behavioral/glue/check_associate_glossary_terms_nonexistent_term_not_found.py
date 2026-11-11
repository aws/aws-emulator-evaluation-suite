"""associate-glossary-terms-nonexistent-term-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "associate-glossary-terms-nonexistent-term-not-found"
GROUP = "error-semantics"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateGlossaryTerms with a term id that was never created fails with InvalidInputException and its
    exact message and leaves the asset without terms, while a real term associates and GetAsset lists it.
    """
    glue = ctx.client("glue")

    # A real business-glossary "Asset", built through the primitives this API is actually
    # defined against (PutFormType -> PutAssetType -> PutAsset). A plain Data Catalog table's
    # ARN does not reliably resolve as an Asset here, so we do not depend on that indexing.
    asset_type_id, asset_id = _put_real_asset(ctx, glue)

    # Positive control setup: a real glossary + term that DOES exist.
    glossary_name = ctx.unique_name("sim2real-glue-glossary-")
    glossary = glue.create_glossary(Name=glossary_name)
    ctx.on_cleanup(lambda: glue.delete_glossary(Identifier=glossary["Id"]))
    term = glue.create_glossary_term(GlossaryIdentifier=glossary["Id"], Name="ApprovedTerm")
    ctx.on_cleanup(lambda: glue.delete_glossary_term(Identifier=term["Id"]))

    fake_term_id = "z9x8y7w6v5u4t3"

    # Negative: associating a term id that was never created is rejected. Real AWS surfaces
    # this as InvalidInputException with a "Glossary term not found" message rather than
    # EntityNotFoundException.
    code, message = _error(
        lambda: glue.associate_glossary_terms(
            AssetIdentifier=asset_id, GlossaryTermIdentifiers=[fake_term_id]
        )
    )
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code!r}"
    expected_message = f'{{"Message":"Glossary term not found: {fake_term_id}"}}'
    assert message == expected_message, (
        f"expected AssociateGlossaryTerms' refusal message {expected_message!r}, got {message!r}"
    )

    # Effect absent: the rejected call attached nothing, checked at the destination via an
    # independent read (GetAsset), not via the mutating call's own response.
    asset_after_negative = glue.get_asset(Identifier=asset_id)
    assert asset_after_negative.get("GlossaryTerms", []) == [], (
        f"expected no glossary terms attached, got {asset_after_negative.get('GlossaryTerms')!r}"
    )

    # Positive control: associating a term id that really exists succeeds, and the association
    # is visible through the same independent read.
    assoc = glue.associate_glossary_terms(
        AssetIdentifier=asset_id, GlossaryTermIdentifiers=[term["Id"]]
    )
    assert term["Id"] in assoc["GlossaryTerms"], (
        f"expected {term['Id']!r} in {assoc['GlossaryTerms']!r}"
    )

    asset_after_positive = glue.get_asset(Identifier=asset_id)
    assert term["Id"] in asset_after_positive["GlossaryTerms"], (
        f"expected {term['Id']!r} in {asset_after_positive['GlossaryTerms']!r}"
    )


def _error(fn) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _word_suffix(ctx):
    return "".join(ch for ch in ctx.unique_name("x") if ch.isalnum())[-12:]


def _put_real_asset(ctx, glue):
    suffix = _word_suffix(ctx)
    form_type_name = f"Sim2RealGlossForm{suffix}"
    glue.put_form_type(
        Name=form_type_name,
        Schema=f"structure {form_type_name} {{\n    note: String\n}}",
    )
    ctx.on_cleanup(lambda: glue.delete_form_type(Identifier=form_type_name))

    asset_type_name = f"Sim2RealGlossAsset{suffix}"
    glue.put_asset_type(
        Name=asset_type_name, Forms={form_type_name: {"FormTypeIdentifier": form_type_name}}
    )
    ctx.on_cleanup(lambda: glue.delete_asset_type(Identifier=asset_type_name))

    asset_id = ctx.unique_name("sim2real-glue-gloss-asset-")
    glue.put_asset(
        AssetTypeId=asset_type_name,
        Identifier=asset_id,
        Name=asset_id,
        Forms={
            form_type_name: {
                "FormTypeId": form_type_name,
                "Content": '{"note":"sim2real"}',
            }
        },
    )
    ctx.on_cleanup(lambda: glue.delete_asset(Identifier=asset_id))

    return asset_type_name, asset_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
