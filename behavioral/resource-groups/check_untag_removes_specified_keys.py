"""untag-removes-specified-keys."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-removes-specified-keys"
GROUP = "tagging"
SERVICES = ["resource-groups"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Untag removes exactly the requested keys and leaves the rest of the tag set intact."""
    rg = ctx.client("resource-groups")
    name = ctx.unique_name("sim2real-rg-untag-")

    query = {
        "Type": "TAG_FILTERS_1_0",
        "Query": '{"ResourceTypeFilters":["AWS::AllSupported"],"TagFilters":[{"Key":"sim2real-untag-nomatch","Values":["' + name + '"]}]}',
    }
    created = rg.create_group(Name=name, ResourceQuery=query, Tags={"Keep": "v1", "Remove": "v2"})
    arn = created["Group"]["GroupArn"]

    def _cleanup():
        # Already deleted by the check body itself is fine; anything else is a real leak signal.
        try:
            rg.delete_group(Group=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    tags0 = rg.get_tags(Arn=arn)["Tags"]
    assert tags0 == {"Keep": "v1", "Remove": "v2"}, f"expected initial tag set, got {tags0!r}"

    rg.untag(Arn=arn, Keys=["Remove"])
    tags1 = rg.get_tags(Arn=arn)["Tags"]
    assert tags1 == {"Keep": "v1"}, f"expected only 'Remove' key gone, got {tags1!r}"

    rg.delete_group(Group=name)
    code, message = _client_error(lambda: rg.get_group(Group=name), expect="NotFoundException")
    assert code == "NotFoundException", f"expected NotFoundException for deleted group, got {code!r}"
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
