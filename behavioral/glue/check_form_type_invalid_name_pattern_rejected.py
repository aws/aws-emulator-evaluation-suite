"""form-type-invalid-name-pattern-rejected."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "form-type-invalid-name-pattern-rejected"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutFormType with a Name that violates the required ^[A-Z]\\w*$ pattern (form type names
    must start with an uppercase letter) is rejected with InvalidInputException and no form type
    is created, while a positive control using a conforming Name succeeds in the same run."""
    glue = ctx.client("glue")

    raw = ctx.unique_name("sim2real-formtype-")
    invalid_name = "lowercase" + "".join(ch for ch in raw if ch.isalnum())
    invalid_schema = f"structure {invalid_name} {{\n    note: String\n}}"

    # Break exactly one thing: an invalid (lowercase-leading) form type Name.
    code, message = _error(lambda: glue.put_form_type(Name=invalid_name, Schema=invalid_schema))
    assert code == "InvalidInputException", (
        f"expected InvalidInputException for Name={invalid_name!r} (violates ^[A-Z]\\w*$), "
        f"got {code!r}"
    )
    expected = (
        '{"Message":"1 validation error detected: Value at \'name\' failed to satisfy constraint: '
        'Member must satisfy regular expression pattern: ^[A-Z]\\\\w*$"}'
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the malformed name never resolves to a real form type.
    code, message = _error(lambda: glue.get_form_type(Identifier=invalid_name))
    assert code == "EntityNotFoundException", (
        f"expected EntityNotFoundException reading rejected Name={invalid_name!r}, got {code!r}"
    )
    expected = f'{{"Message":"Metadata form type {invalid_name} not found."}}'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: a conforming Name (starts with an uppercase letter) succeeds.
    valid_name = "Sim" + "".join(ch for ch in raw if ch.isalnum())
    valid_schema = f"structure {valid_name} {{\n    note: String\n}}"
    created = glue.put_form_type(Name=valid_name, Schema=valid_schema)
    form_type_id = created["Id"]
    assert created["Name"] == valid_name, (
        f"expected PutFormType to echo Name={valid_name!r}, got {created['Name']!r}"
    )

    def _cleanup():
        from botocore.exceptions import ClientError

        try:
            glue.delete_form_type(Identifier=form_type_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "EntityNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    got_name = glue.get_form_type(Identifier=form_type_id)["Name"]
    assert got_name == valid_name, (
        f"expected independent GetFormType({form_type_id!r}) to return Name={valid_name!r}, "
        f"got {got_name!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError rejection, but the call SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
