"""lookup-table-duplicate-name-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lookup-table-duplicate-name-rejected"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateLookupTable with a taken name is refused with ResourceAlreadyExistsException and
    leaves the original body; after delete, reads and updates get ResourceNotFoundException and the
    same name is creatable again with the same ARN.
    """
    logs = ctx.client("logs")
    table_name = ctx.unique_name("sim2real_dup_lookup_").replace("-", "_")

    # positive control: creating under a fresh name works at all
    create_resp = logs.create_lookup_table(
        lookupTableName=table_name, tableBody="k,v\noriginal,1\n"
    )
    table_arn = create_resp["lookupTableArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_lookup_table(lookupTableArn=table_arn)))

    # a second table under the same name must be rejected
    code, code_msg = _error_code(
        lambda: logs.create_lookup_table(lookupTableName=table_name, tableBody="k,v\nsecond,2\n")
    )
    assert code == "ResourceAlreadyExistsException", f"expected ResourceAlreadyExistsException, got {code!r}"
    expected = f"Lookup table '{table_name}' already exists in account '{ctx.account}'"
    assert code_msg == expected, f"expected message {expected!r}, got {code_msg!r}"

    # the rejected attempt did not touch the original's content
    got = logs.get_lookup_table(lookupTableArn=table_arn)
    assert "original,1" in got["tableBody"], f"expected original content preserved, got {got['tableBody']!r}"
    assert "second,2" not in got["tableBody"], f"rejected write leaked into stored content: {got['tableBody']!r}"

    # restore: remove the original, which was the actual source of the conflict
    logs.delete_lookup_table(lookupTableArn=table_arn)

    # independent read confirms it is gone
    gone_code, gone_code_msg = _error_code(lambda: logs.get_lookup_table(lookupTableArn=table_arn))
    assert gone_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {gone_code!r}"
    )
    expected_gone = f"Lookup table '{table_name}' not found in account '{ctx.account}'"
    assert gone_code_msg == expected_gone, f"expected message {expected_gone!r}, got {gone_code_msg!r}"

    # a mutation on the dead id also fails, not just a read
    dead_mutation_code, dead_mutation_code_msg = _error_code(lambda: logs.delete_lookup_table(lookupTableArn=table_arn))
    assert dead_mutation_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting an already-deleted lookup table, got {dead_mutation_code!r}"
    )
    assert dead_mutation_code_msg == expected_gone, (
        f"expected message {expected_gone!r}, got {dead_mutation_code_msg!r}"
    )

    # the identical call that was rejected above succeeds once the original is gone: the
    # name was only unavailable while the original held it. The lookup table ARN is
    # derived from the name, not a fresh opaque id per create, so the recreated table
    # reuses the original ARN.
    second_resp = logs.create_lookup_table(lookupTableName=table_name, tableBody="k,v\nsecond,2\n")
    second_arn = second_resp["lookupTableArn"]
    assert second_arn == table_arn, (
        f"expected the recreated table's ARN to reuse the name-derived ARN {table_arn!r}, got {second_arn!r}"
    )

    # terminal independent read: the recreated table carries the new content under the same name
    second_got = logs.get_lookup_table(lookupTableArn=second_arn)
    assert second_got["lookupTableName"] == table_name, (
        f"expected recreated table named {table_name!r}, got {second_got['lookupTableName']!r}"
    )
    assert "second,2" in second_got["tableBody"], (
        f"expected recreated table content, got {second_got['tableBody']!r}"
    )


def _error_code(fn):
    """The AWS (code, message) fn() raised. An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call was expected to be refused but it succeeded, returning {result!r}")


def _safe_call(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
