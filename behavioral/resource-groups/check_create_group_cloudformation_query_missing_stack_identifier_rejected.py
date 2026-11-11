"""create-group-cloudformation-query-missing-stack-identifier-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-group-cloudformation-query-missing-stack-identifier-rejected"
GROUP = "overly-permissive"
SERVICES = ["resource-groups"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGroup rejects a CLOUDFORMATION_STACK_1_0 query whose Query JSON omits the
    required StackIdentifier field; an otherwise-identical query that includes it succeeds."""
    rg = ctx.client("resource-groups")

    bad_name = ctx.unique_name("sim2real-rg-cfnbadquery-")
    bad_query = {
        "Type": "CLOUDFORMATION_STACK_1_0",
        # Missing StackIdentifier -- structurally invalid for this query type.
        "Query": json.dumps({"ResourceTypeFilters": ["AWS::AllSupported"]}),
    }
    code, message = _client_error(
        lambda: rg.create_group(Name=bad_name, ResourceQuery=bad_query), expect="BadRequestException"
    )
    assert code == "BadRequestException", f"expected BadRequestException for missing StackIdentifier, got {code!r}"
    assert message == "Query not valid: Query format not valid: check JSON syntax", (
        f"CreateGroup with missing StackIdentifier returned message {message!r}"
    )

    # Effect absent: no group was created under that name.
    code_get, message_get = _client_error(lambda: rg.get_group(Group=bad_name), expect="NotFoundException")
    assert code_get == "NotFoundException", f"expected NotFoundException for {bad_name!r}, got {code_get!r}"
    assert message_get == "The specified group does not exist", f"GetGroup {bad_name!r} returned message {message_get!r}"

    # Positive control: CreateGroup succeeds in general (a well-formed TAG_FILTERS_1_0 query),
    # isolating the failure above to the malformed CLOUDFORMATION_STACK_1_0 query body itself.
    good_name = ctx.unique_name("sim2real-rg-cfngoodquery-")
    good_query = {
        "Type": "TAG_FILTERS_1_0",
        "Query": json.dumps(
            {"ResourceTypeFilters": ["AWS::AllSupported"], "TagFilters": [{"Key": "marker", "Values": [good_name]}]}
        ),
    }
    rg.create_group(Name=good_name, ResourceQuery=good_query, Tags={"sim2real": good_name})
    ctx.on_cleanup(lambda: rg.delete_group(Group=good_name))
    gq = rg.get_group_query(Group=good_name)["GroupQuery"]["ResourceQuery"]
    assert gq["Type"] == "TAG_FILTERS_1_0", f"expected TAG_FILTERS_1_0 on positive control, got {gq['Type']!r}"


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
