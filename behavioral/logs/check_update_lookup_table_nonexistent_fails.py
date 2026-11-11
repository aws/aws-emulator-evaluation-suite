"""update-lookup-table-nonexistent-fails."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-lookup-table-nonexistent-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateLookupTable replaces a real table's body, and on an ARN with no table it is refused with
    ResourceNotFoundException and its exact message instead of creating one.
    """
    logs = ctx.client("logs")

    name = ctx.unique_name("sim2real_behav_lookuptbl_").replace("-", "_")
    csv_v1 = "key,value\nfoo,bar\n"
    create_resp = logs.create_lookup_table(
        lookupTableName=name,
        tableBody=csv_v1,
        tags={"sim2real": CHECK},
    )
    arn = create_resp["lookupTableArn"]
    ctx.on_cleanup(lambda: _safe_delete_lookup_table(logs, arn))

    # positive control: UpdateLookupTable on a real table actually replaces content
    csv_v2 = "key,value\nfoo,baz\n"
    logs.update_lookup_table(lookupTableArn=arn, tableBody=csv_v2)
    updated = logs.get_lookup_table(lookupTableArn=arn)
    assert updated["tableBody"] == csv_v2, (
        f"UpdateLookupTable on a real table did not replace content, got "
        f"{updated.get('tableBody')!r}"
    )

    # UpdateLookupTable requires tableBody (a full replace of the table's
    # contents); omitting it triggers parameter validation before the
    # service ever checks whether the ARN refers to an existing table, which
    # would mask the ResourceNotFoundException this check is meant to
    # exercise. Supply a syntactically valid body so the only thing wrong
    # with the request is the nonexistent ARN.
    #
    # The fake ARN is derived from the real one (same account/region, a name
    # that was never created) instead of fabricated from scratch, so it can't
    # land outside this identity's resource scope and surface
    # AccessDeniedException instead of the not-found semantics under test.
    fake_arn = arn.rsplit(":", 1)[0] + ":" + name + "_absent"
    code, message = _client_error(
        lambda: logs.update_lookup_table(
            lookupTableArn=fake_arn, tableBody="key,value\nfoo,bar\n"
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for UpdateLookupTable on an unknown "
        f"ARN, got {code}"
    )
    assert message == (
        f"Lookup table '{name}_absent' not found in account '{ctx.account}'"
    ), (
        f"unexpected UpdateLookupTable not-found message: {message!r}"
    )


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected UpdateLookupTable to fail, but it SUCCEEDED and returned {result!r}"
    )


def _safe_delete_lookup_table(logs: Any, arn: str) -> None:
    try:
        logs.delete_lookup_table(lookupTableArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
