"""glossary-term-lifecycle-create-associate-delete."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "glossary-term-lifecycle-create-associate-delete"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateGlossaryTerms attaches a created term to an asset (GetAsset lists it after an empty
    start), and after DeleteGlossaryTerm GetGlossaryTerm raises EntityNotFoundException with the
    exact message.
    """
    glue = ctx.client("glue")
    glossary_name = ctx.unique_name("sim2real-behav-glossary-assoc-")
    term_name = ctx.unique_name("sim2real-behav-term-assoc-")
    asset_id = ctx.unique_name("sim2real-behav-asset-assoc-")
    suffix = ctx.unique_name("s2r")[3:]
    form_type_name = f"Sim2RealBehavClassification{suffix}"
    asset_type_name = f"Sim2RealBehavDataSet{suffix}"

    glossary_id = glue.create_glossary(Name=glossary_name)["Id"]
    ctx.on_cleanup(lambda: _delete_glossary_ignore_missing(glue, glossary_id))

    term = glue.create_glossary_term(
        GlossaryIdentifier=glossary_id,
        Name=term_name,
        ShortDescription="a term used for association testing",
    )
    term_id = term["Id"]
    ctx.on_cleanup(lambda: _delete_term_ignore_missing(glue, term_id))

    glue.put_form_type(
        Name=form_type_name,
        Schema=f"structure {form_type_name} {{\n    classification: String\n}}",
    )
    ctx.on_cleanup(lambda: _delete_form_type_ignore_missing(glue, form_type_name))
    glue.put_asset_type(
        Name=asset_type_name,
        Forms={"Classification": {"FormTypeIdentifier": form_type_name}},
    )
    ctx.on_cleanup(lambda: _delete_asset_type_ignore_missing(glue, asset_type_name))

    glue.put_asset(
        AssetTypeId=asset_type_name,
        Identifier=asset_id,
        Name=asset_id,
        Forms={
            "Classification": {
                "FormTypeId": form_type_name,
                "Content": json.dumps({"classification": "internal"}),
            }
        },
    )
    ctx.on_cleanup(lambda: _delete_asset_ignore_missing(glue, asset_id))

    before = glue.get_asset(Identifier=asset_id)
    assert before["GlossaryTerms"] == []

    assoc = glue.associate_glossary_terms(
        AssetIdentifier=asset_id, GlossaryTermIdentifiers=[term_id]
    )
    assert assoc["GlossaryTerms"] == [term_id]

    after = glue.get_asset(Identifier=asset_id)
    assert term_id in after["GlossaryTerms"]

    glue.delete_glossary_term(Identifier=term_id)
    code, message = _error(lambda: glue.get_glossary_term(Identifier=term_id))
    assert code == "EntityNotFoundException"
    expected = f'{{"Message":"Business glossary term {term_id} not found."}}'
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises, so an emulator accepting what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _delete_glossary_ignore_missing(glue, glossary_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        glue.delete_glossary(Identifier=glossary_id)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("EntityNotFoundException", "ConflictException"):
            raise


def _delete_term_ignore_missing(glue, term_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        glue.delete_glossary_term(Identifier=term_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _delete_asset_ignore_missing(glue, asset_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        glue.delete_asset(Identifier=asset_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _delete_asset_type_ignore_missing(glue, asset_type_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        glue.delete_asset_type(Identifier=asset_type_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _delete_form_type_ignore_missing(glue, form_type_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        glue.delete_form_type(Identifier=form_type_name)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("EntityNotFoundException", "ConflictException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
