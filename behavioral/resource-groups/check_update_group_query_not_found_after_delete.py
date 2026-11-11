"""update-group-query-not-found-after-delete."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-group-query-not-found-after-delete"
GROUP = "error-semantics"
SERVICES = ["resource-groups"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateGroupQuery succeeds on a live group and raises NotFoundException once it is deleted."""
    rg = ctx.client("resource-groups")
    name = ctx.unique_name("sim2real-rg-uqnf-")

    def make_query(tag_value):
        return {
            "Type": "TAG_FILTERS_1_0",
            "Query": json.dumps(
                {"ResourceTypeFilters": ["AWS::AllSupported"], "TagFilters": [{"Key": "marker", "Values": [tag_value]}]}
            ),
        }

    rg.create_group(Name=name, ResourceQuery=make_query("v1"))

    def _cleanup():
        # Already deleted by the check body itself is fine; anything else is a real leak signal.
        try:
            rg.delete_group(Group=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    rg.update_group_query(Group=name, ResourceQuery=make_query("v2"))
    gq = rg.get_group_query(Group=name)["GroupQuery"]["ResourceQuery"]
    got_values = json.loads(gq["Query"])["TagFilters"][0]["Values"]
    assert got_values == ["v2"], f"expected updated query tag value ['v2'], got {got_values}"

    rg.delete_group(Group=name)

    # Independent read confirms the group itself is gone, not just that one mutation was rejected.
    code_read, message_read = _client_error(lambda: rg.get_group_query(Group=name), expect="NotFoundException")
    assert code_read == "NotFoundException", f"expected NotFoundException from GetGroupQuery on deleted group, got {code_read!r}"
    assert message_read == "The specified group does not exist", (
        f"GetGroupQuery on deleted group returned message {message_read!r}"
    )

    code, message = _client_error(
        lambda: rg.update_group_query(Group=name, ResourceQuery=make_query("v3")), expect="NotFoundException"
    )
    assert code == "NotFoundException", f"expected NotFoundException from UpdateGroupQuery on deleted group, got {code!r}"
    assert message == "The specified group does not exist", (
        f"UpdateGroupQuery on deleted group returned message {message!r}"
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
