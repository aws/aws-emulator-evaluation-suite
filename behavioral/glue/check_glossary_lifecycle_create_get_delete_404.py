"""glossary-lifecycle-create-get-delete-404."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "glossary-lifecycle-create-get-delete-404"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGlossary succeeds, GetGlossary reflects it, DeleteGlossary removes it, a
    subsequent GetGlossary raises EntityNotFoundException, and a mutation (UpdateGlossary)
    against the deleted id fails the same way a read does."""
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real-glossary-")

    created = glue.create_glossary(Name=name, Description="behavioral fidelity check")
    glossary_id = created["Id"]
    assert created["Name"] == name, f"expected Name {name!r}, got {created['Name']!r}"

    ctx.on_cleanup(lambda: _ignore_missing(lambda: glue.delete_glossary(Identifier=glossary_id)))

    got = glue.get_glossary(Identifier=glossary_id)
    assert got["Id"] == glossary_id, f"expected Id {glossary_id!r}, got {got['Id']!r}"
    assert got["Name"] == name, f"expected Name {name!r}, got {got['Name']!r}"
    assert got["Description"] == "behavioral fidelity check", (
        f"expected Description 'behavioral fidelity check', got {got['Description']!r}"
    )

    glue.delete_glossary(Identifier=glossary_id)

    code, message = _error(lambda: glue.get_glossary(Identifier=glossary_id))
    assert code == "EntityNotFoundException", (
        f"expected EntityNotFoundException from GetGlossary on deleted id, got {code!r}"
    )
    expected = f'{{"Message":"Business glossary {glossary_id} not found."}}'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code, message = _error(lambda: glue.update_glossary(Identifier=glossary_id, Description="post-delete update"))
    assert code == "EntityNotFoundException", (
        f"expected EntityNotFoundException from UpdateGlossary on deleted id, got {code!r}"
    )
    expected = f'{{"Message":"Business glossary {glossary_id} not found."}}'
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


def _ignore_missing(fn):
    """Run a teardown call; a resource that is already gone is not a leak."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
