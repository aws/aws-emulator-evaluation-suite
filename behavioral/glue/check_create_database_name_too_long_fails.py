"""create-database-name-too-long-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-database-name-too-long-fails"
GROUP = 'overly-permissive'
SERVICES = ['glue']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDatabase with a 300-character name is rejected with ValidationException and its exact message and
    GetDatabase on that name fails the same way, while a valid name creates a database.
    """
    glue = ctx.client("glue")

    good_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": good_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=good_name))
    got = glue.get_database(Name=good_name)["Database"]["Name"]
    assert got == good_name, f"positive control: expected {good_name!r}, got {got!r}"

    too_long = "a" * 300
    code, message = _error(lambda: glue.create_database(DatabaseInput={"Name": too_long}))
    assert code == "ValidationException", (
        f"expected ValidationException for a 300-char database name, got {code}"
    )
    assert message == (
        f"1 validation error detected: Value '{too_long}' at 'database.name' failed to satisfy "
        "constraint: Member must have length less than or equal to 255"
    ), f"unexpected CreateDatabase message: {message!r}"

    # GetDatabase validates the same name shape as CreateDatabase, so the too-long
    # name is rejected before any existence check is even reached -- not "not found".
    get_code, get_message = _error(lambda: glue.get_database(Name=too_long))
    assert get_code == "ValidationException", (
        f"expected the too-long name to be rejected by GetDatabase too, got {get_code}"
    )
    assert get_message == (
        f"1 validation error detected: Value '{too_long}' at 'name' failed to satisfy "
        "constraint: Member must have length less than or equal to 255"
    ), f"unexpected GetDatabase message: {get_message!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, because an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
