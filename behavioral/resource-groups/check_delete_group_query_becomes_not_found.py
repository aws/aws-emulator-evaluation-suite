"""delete-group-query-becomes-not-found."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-group-query-becomes-not-found"
GROUP = "state"
SERVICES = ["resource-groups"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteGroup removes the group's query along with the group (ACTIVE -> DELETED)."""
    rg = ctx.client("resource-groups")
    name = ctx.unique_name("sim2real-rg-delquery-")
    query = {
        "Type": "TAG_FILTERS_1_0",
        "Query": json.dumps(
            {"ResourceTypeFilters": ["AWS::AllSupported"], "TagFilters": [{"Key": "marker", "Values": [name]}]}
        ),
    }
    rg.create_group(Name=name, ResourceQuery=query)

    def _cleanup():
        # Already deleted by the check body itself is fine; anything else is a real leak signal.
        try:
            rg.delete_group(Group=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    before = rg.get_group_query(Group=name)
    got_name = before["GroupQuery"]["GroupName"]
    assert got_name == name, f"expected GetGroupQuery to report GroupName {name!r}, got {got_name!r}"

    rg.delete_group(Group=name)

    code_group, message_group = _client_error(lambda: rg.get_group(Group=name), expect="NotFoundException")
    assert code_group == "NotFoundException", f"expected NotFoundException from GetGroup on deleted group, got {code_group!r}"
    assert message_group == "The specified group does not exist", (
        f"GetGroup on deleted group returned message {message_group!r}"
    )

    code_query, message_query = _client_error(lambda: rg.get_group_query(Group=name), expect="NotFoundException")
    assert code_query == "NotFoundException", f"expected NotFoundException from GetGroupQuery on deleted group, got {code_query!r}"
    assert message_query == "The specified group does not exist", (
        f"GetGroupQuery on deleted group returned message {message_query!r}"
    )


def _client_error(fn, *, expect):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises, so an emulator accepting what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected {expect} but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
