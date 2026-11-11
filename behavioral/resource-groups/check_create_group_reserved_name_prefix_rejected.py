"""create-group-reserved-name-prefix-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-group-reserved-name-prefix-rejected"
GROUP = "overly-permissive"
SERVICES = ["resource-groups"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGroup rejects a Name starting with the reserved 'aws' prefix, case-insensitively."""
    rg = ctx.client("resource-groups")
    suffix = ctx.unique_name("sim2real-rgname-").rsplit("-", 1)[-1]
    bad_name = f"aws-reserved-{suffix}"
    bad_name_mixed_case = f"AwS-Reserved-{suffix}"

    query = {
        "Type": "TAG_FILTERS_1_0",
        "Query": '{"ResourceTypeFilters":["AWS::AllSupported"],"TagFilters":[{"Key":"sim2real-reserved-nomatch","Values":["' + suffix + '"]}]}',
    }

    code, message = _client_error(
        lambda: rg.create_group(Name=bad_name, ResourceQuery=query), expect="BadRequestException"
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException creating reserved-prefixed group {bad_name!r}, got {code!r}"
    )
    assert message == "Group name must not start with 'AWS'", (
        f"CreateGroup {bad_name!r} returned message {message!r}"
    )

    # The reservation is documented as case-insensitive ("AWS", "aws", or any other
    # capitalization) — prove it on a mixed-case prefix, not just the lowercase one.
    code_mixed, message_mixed = _client_error(
        lambda: rg.create_group(Name=bad_name_mixed_case, ResourceQuery=query), expect="BadRequestException"
    )
    assert code_mixed == "BadRequestException", (
        f"expected BadRequestException creating mixed-case reserved-prefixed group "
        f"{bad_name_mixed_case!r}, got {code_mixed!r}"
    )
    assert message_mixed == "Group name must not start with 'AWS'", (
        f"CreateGroup {bad_name_mixed_case!r} returned message {message_mixed!r}"
    )

    # Effect absent: no group with either reserved-prefixed name was created.
    code_get, message_get = _client_error(lambda: rg.get_group(Group=bad_name), expect="NotFoundException")
    assert code_get == "NotFoundException", (
        f"expected NotFoundException reading rejected group {bad_name!r}, got {code_get!r}"
    )
    assert message_get == "The specified group does not exist", (
        f"GetGroup {bad_name!r} returned message {message_get!r}"
    )
    code_get_mixed, message_get_mixed = _client_error(
        lambda: rg.get_group(Group=bad_name_mixed_case), expect="NotFoundException"
    )
    assert code_get_mixed == "NotFoundException", (
        f"expected NotFoundException reading rejected group {bad_name_mixed_case!r}, "
        f"got {code_get_mixed!r}"
    )
    assert message_get_mixed == "The specified group does not exist", (
        f"GetGroup {bad_name_mixed_case!r} returned message {message_get_mixed!r}"
    )

    # Positive control: an otherwise-identical, non-reserved name succeeds.
    good_name = f"sim2real-reserved-{suffix}"
    rg.create_group(Name=good_name, ResourceQuery=query)
    ctx.on_cleanup(lambda: rg.delete_group(Group=good_name))
    live = rg.get_group(Group=good_name)
    assert live["Group"]["Name"] == good_name, (
        f"expected control group {good_name!r} to exist, got {live['Group']!r}"
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
