"""create-group-mutually-exclusive-query-and-configuration-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-group-mutually-exclusive-query-and-configuration-rejected"
GROUP = "overly-permissive"
SERVICES = ["resource-groups"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGroup rejects a request supplying both ResourceQuery and Configuration."""
    rg = ctx.client("resource-groups")
    name = ctx.unique_name("sim2real-rg-mutex-")

    query = {
        "Type": "TAG_FILTERS_1_0",
        "Query": json.dumps(
            {"ResourceTypeFilters": ["AWS::AllSupported"], "TagFilters": [{"Key": "marker", "Values": [name]}]}
        ),
    }
    configuration = [
        {
            "Type": "AWS::ResourceGroups::Generic",
            "Parameters": [{"Name": "allowed-resource-types", "Values": ["AWS::EC2::Host"]}],
        }
    ]

    code, message = _client_error(
        lambda: rg.create_group(Name=name, ResourceQuery=query, Configuration=configuration),
        expect="BadRequestException",
    )
    assert code == "BadRequestException", (
        f"CreateGroup with both ResourceQuery and Configuration should be rejected, got {code!r}"
    )
    assert message == "Please use only 'configuration' or 'query' in the request, but not both.", (
        f"CreateGroup with both ResourceQuery and Configuration returned message {message!r}"
    )

    # Effect absent: the group was never created.
    code_get, message_get = _client_error(lambda: rg.get_group(Group=name), expect="NotFoundException")
    assert code_get == "NotFoundException", (
        f"group {name!r} must not exist after the mutually-exclusive CreateGroup was rejected, "
        f"got {code_get!r}"
    )
    assert message_get == "The specified group does not exist", (
        f"GetGroup on never-created group {name!r} returned message {message_get!r}"
    )

    # Positive control: the same Name+ResourceQuery succeeds when Configuration is omitted.
    rg.create_group(Name=name, ResourceQuery=query)
    ctx.on_cleanup(lambda: rg.delete_group(Group=name))
    live = rg.get_group(Group=name)
    assert live["Group"]["Name"] == name, (
        f"positive-control group {name!r} should exist with that name, got {live['Group']!r}"
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
