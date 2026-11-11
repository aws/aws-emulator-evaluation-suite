"""get-group-not-found-after-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-group-not-found-after-delete"
GROUP = "error-semantics"
SERVICES = ["resource-groups"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetGroup succeeds for a live group and raises NotFoundException for the same name once deleted."""
    rg = ctx.client("resource-groups")
    name = ctx.unique_name("sim2real-rg-notfound-")

    query = {
        "Type": "TAG_FILTERS_1_0",
        "Query": '{"ResourceTypeFilters":["AWS::AllSupported"],"TagFilters":[{"Key":"sim2real-notfound-nomatch","Values":["' + name + '"]}]}',
    }
    rg.create_group(Name=name, ResourceQuery=query, Tags={"sim2real-check": CHECK})

    def _cleanup():
        # Already deleted by the check body itself is fine; anything else is a real leak signal.
        try:
            rg.delete_group(Group=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    live = rg.get_group(Group=name)
    assert live["Group"]["Name"] == name, f"expected live group named {name!r}, got {live['Group'].get('Name')!r}"

    rg.delete_group(Group=name)

    code, message = _client_error(lambda: rg.get_group(Group=name), expect="NotFoundException")
    assert code == "NotFoundException", f"expected GetGroup on a deleted group to raise NotFoundException, got {code!r}"
    assert message == "The specified group does not exist", f"GetGroup on a deleted group returned message {message!r}"


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
