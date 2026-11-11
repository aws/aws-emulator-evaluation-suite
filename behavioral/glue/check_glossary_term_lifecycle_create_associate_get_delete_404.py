"""glossary-term-lifecycle-create-associate-get-delete-404."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "glossary-term-lifecycle-create-associate-get-delete-404"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateGlossaryTerms links a new term to an asset, which GetAsset reflects exactly; after
    DeleteGlossaryTerm, GetGlossaryTerm raises EntityNotFoundException and re-associating the
    deleted term raises InvalidInputException."""
    glue = ctx.client("glue")

    glossary_name = ctx.unique_name("sim2real-glossary-")
    glossary_id = glue.create_glossary(Name=glossary_name)["Id"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: glue.delete_glossary(Identifier=glossary_id)))

    term_name = ctx.unique_name("sim2real-term-")
    created_term = glue.create_glossary_term(
        GlossaryIdentifier=glossary_id,
        Name=term_name,
        ShortDescription="a term for behavioral fidelity testing",
    )
    term_id = created_term["Id"]
    assert created_term["GlossaryId"] == glossary_id, (
        f"expected GlossaryId={glossary_id!r}, got {created_term['GlossaryId']!r}"
    )

    ctx.on_cleanup(lambda: _ignore_missing(lambda: glue.delete_glossary_term(Identifier=term_id)))

    form_type_id, form_type_name = _create_form_type(ctx, glue)
    asset_type_id = _create_asset_type(ctx, glue, form_type_name, form_type_id)
    asset_id = _create_asset(ctx, glue, asset_type_id, form_type_id, form_type_name)

    before_asset = glue.get_asset(Identifier=asset_id)
    assert before_asset.get("GlossaryTerms", []) == [], (
        f"expected no glossary terms before association, got {before_asset.get('GlossaryTerms')!r}"
    )

    assoc = glue.associate_glossary_terms(
        AssetIdentifier=asset_id, GlossaryTermIdentifiers=[term_id]
    )
    assert assoc["GlossaryTerms"] == [term_id], (
        f"expected associate_glossary_terms to echo [{term_id!r}], got {assoc['GlossaryTerms']!r}"
    )

    got_asset = glue.get_asset(Identifier=asset_id)
    assert got_asset["GlossaryTerms"] == [term_id], (
        f"expected GetAsset to reflect [{term_id!r}], got {got_asset.get('GlossaryTerms')!r}"
    )

    got_term = glue.get_glossary_term(Identifier=term_id)
    assert got_term["Id"] == term_id, f"expected Id={term_id!r}, got {got_term['Id']!r}"
    assert got_term["Name"] == term_name, (
        f"expected Name={term_name!r}, got {got_term['Name']!r}"
    )

    glue.delete_glossary_term(Identifier=term_id)

    code, message = _error(lambda: glue.get_glossary_term(Identifier=term_id))
    assert code == "EntityNotFoundException", (
        f"expected GetGlossaryTerm on a deleted term to raise EntityNotFoundException, got {code!r}"
    )
    expected = f'{{"Message":"Business glossary term {term_id} not found."}}'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    reassoc_code, reassoc_message = _error(
        lambda: glue.associate_glossary_terms(
            AssetIdentifier=asset_id, GlossaryTermIdentifiers=[term_id]
        )
    )
    assert reassoc_code == "InvalidInputException", (
        "expected AssociateGlossaryTerms with a deleted term id to raise "
        f"InvalidInputException, got {reassoc_code!r}"
    )
    expected = f'{{"Message":"Glossary term not found: {term_id}"}}'
    assert reassoc_message == expected, f"expected message {expected!r}, got {reassoc_message!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _ignore_missing(fn, *also):
    """Run a teardown call; a resource that is already gone (or one of the codes in `also`)
    is not a failure."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("EntityNotFoundException", *also):
            raise


def _pascal_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    cleaned = "".join(ch for ch in raw if ch.isalnum())
    return "Sim" + cleaned


def _create_form_type(ctx, glue):
    name = _pascal_name(ctx, "sim2real-formtype-")
    schema = f"structure {name} {{\n    note: String\n}}"
    resp = glue.put_form_type(Name=name, Schema=schema)
    form_type_id = resp["Id"]

    ctx.on_cleanup(
        lambda: _ignore_missing(
            lambda: glue.delete_form_type(Identifier=form_type_id), "ConflictException"
        )
    )
    return form_type_id, name


def _create_asset_type(ctx, glue, form_key_name, form_type_id):
    name = _pascal_name(ctx, "sim2real-assettype-")
    resp = glue.put_asset_type(
        Name=name, Forms={form_key_name: {"FormTypeIdentifier": form_type_id}}
    )
    asset_type_id = resp["Id"]

    ctx.on_cleanup(lambda: _ignore_missing(lambda: glue.delete_asset_type(Identifier=asset_type_id)))
    return asset_type_id


def _create_asset(ctx, glue, asset_type_id, form_type_id, form_key_name):
    asset_id = ctx.unique_name("sim2real-asset-")
    resp = glue.put_asset(
        AssetTypeId=asset_type_id,
        Identifier=asset_id,
        Name="behavioral-fidelity-asset",
        Forms={form_key_name: {"FormTypeId": form_type_id, "Content": "{}"}},
    )

    ctx.on_cleanup(lambda: _ignore_missing(lambda: glue.delete_asset(Identifier=asset_id)))
    return resp["Id"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
