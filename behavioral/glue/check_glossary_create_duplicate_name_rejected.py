"""glossary-create-duplicate-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "glossary-create-duplicate-name-rejected"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGlossary with a Name that already exists in the account is rejected with
    AlreadyExistsException, the original glossary is left untouched, and a positive control
    (create with a different Name) succeeds in the same run."""
    glue = ctx.client("glue")

    name = ctx.unique_name("sim2real-glossary-")
    original = glue.create_glossary(Name=name, Description="original")
    glossary_id = original["Id"]

    ctx.on_cleanup(lambda: _ignore_missing(lambda: glue.delete_glossary(Identifier=glossary_id)))

    # Break exactly one thing: try to create a second glossary with the same Name.
    code, message = _error(lambda: glue.create_glossary(Name=name, Description="duplicate"))
    assert code == "AlreadyExistsException", f"expected AlreadyExistsException, got {code}"
    expected = f'{{"Message":"A glossary with name \'{name}\' already exists."}}'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the original glossary is unchanged, no duplicate was merged into it.
    still_original = glue.get_glossary(Identifier=glossary_id)
    assert still_original["Description"] == "original", (
        f"expected original description unchanged, got {still_original['Description']!r}"
    )

    # Positive control: creating a glossary with a distinct Name succeeds.
    other_name = ctx.unique_name("sim2real-glossary-other-")
    other = glue.create_glossary(Name=other_name, Description="distinct")
    other_id = other["Id"]

    ctx.on_cleanup(lambda: _ignore_missing(lambda: glue.delete_glossary(Identifier=other_id)))

    assert other_id != glossary_id, f"expected distinct id, got same id {other_id!r} twice"
    fetched_other = glue.get_glossary(Identifier=other_id)["Name"]
    assert fetched_other == other_name, f"expected Name {other_name!r}, got {fetched_other!r}"


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
