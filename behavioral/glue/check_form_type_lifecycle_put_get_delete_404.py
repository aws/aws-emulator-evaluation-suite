"""form-type-lifecycle-put-get-delete-404."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "form-type-lifecycle-put-get-delete-404"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutFormType creates a governance form type, GetFormType returns it, DeleteFormType
    removes it, a subsequent GetFormType raises EntityNotFoundException, and DeleteFormType is
    idempotent: a repeat delete of the same dead id succeeds rather than erroring."""
    glue = ctx.client("glue")
    name = _pascal_name(ctx, "sim2real-formtype-")
    schema = f"structure {name} {{\n    note: String\n}}"

    created = glue.put_form_type(Name=name, Schema=schema)
    form_type_id = created["Id"]
    assert created["Name"] == name, f"expected PutFormType Name={name!r}, got {created['Name']!r}"

    def _cleanup():
        # The body already deleted it; a repeat delete succeeds or reports not-found.
        try:
            glue.delete_form_type(Identifier=form_type_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "EntityNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    got = glue.get_form_type(Identifier=form_type_id)
    assert got["Id"] == form_type_id, f"expected GetFormType Id={form_type_id!r}, got {got['Id']!r}"
    assert got["Name"] == name, f"expected GetFormType Name={name!r}, got {got['Name']!r}"
    assert "note" in got["Schema"], f"expected field 'note' in returned Schema, got {got['Schema']!r}"

    glue.delete_form_type(Identifier=form_type_id)

    get_code, get_message = _expect_error(lambda: glue.get_form_type(Identifier=form_type_id))
    assert get_code == "EntityNotFoundException", (
        f"expected GetFormType on a deleted id to raise EntityNotFoundException, got {get_code}"
    )
    expected = f'{{"Message":"Metadata form type {form_type_id} not found."}}'
    assert get_message == expected, f"expected message {expected!r}, got {get_message!r}"

    try:
        glue.delete_form_type(Identifier=form_type_id)
    except ClientError as e:
        raise AssertionError(
            "expected a repeat DeleteFormType on an already-deleted id to succeed "
            f"(idempotent), got {e.response['Error']['Code']}"
        ) from e


def _expect_error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected an error, but the call succeeded and returned {result!r}")


def _pascal_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    cleaned = "".join(ch for ch in raw if ch.isalnum())
    return "Sim" + cleaned


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
