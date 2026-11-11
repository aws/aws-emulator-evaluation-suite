"""reject-delete-nonexistent-database."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "reject-delete-nonexistent-database"
GROUP = 'overly-permissive'
SERVICES = ['glue']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After a database is deleted once, DeleteDatabase and GetDatabase on its name raise
    EntityNotFoundException ("Database <name> not found.").
    """
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real-behav-no-such-db-")

    glue.create_database(DatabaseInput={"Name": name})

    def _cleanup() -> None:
        from botocore.exceptions import ClientError

        try:
            glue.delete_database(Name=name)
        except ClientError as err:
            if err.response["Error"]["Code"] != "EntityNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    # Positive control: deleting the real, existing database succeeds.
    glue.delete_database(Name=name)

    # Negative: deleting the now-nonexistent database must fail, not no-op.
    code, message = _error(lambda: glue.delete_database(Name=name))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}"
    assert message == f"Database {name} not found.", message

    # Effect absent: an independent read confirms it stayed gone, not resurrected.
    get_code, get_message = _error(lambda: glue.get_database(Name=name))
    assert get_code == "EntityNotFoundException", (
        f"expected get_database to report EntityNotFoundException after delete, got {get_code}"
    )
    assert get_message == f"Database {name} not found.", get_message


def _error(fn: Any) -> tuple[str, str]:
    """Call fn() and return (code, message) of the refusal; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
