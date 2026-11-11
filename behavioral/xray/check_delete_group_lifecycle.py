"""delete-group-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-group-lifecycle"
GROUP = 'groups'
SERVICES = ['xray']


def _client_error(fn):
    """Call fn(); return its botocore Error dict plus the HTTPStatusCode. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return {**exc.response.get("Error", {}), "HTTPStatusCode": status}
    raise AssertionError(f"expected this call against the deleted group to fail, but it SUCCEEDED and returned {result!r}")


def _group_names(xr):
    return [g["GroupName"] for page in xr.get_paginator("get_groups").paginate() for g in page.get("Groups", [])]


def _delete_if_present(xr, name):
    try:
        xr.delete_group(GroupName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidRequestException":
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created group reads back with its filter and a structural ARN; once deleted it
    disappears from GetGroups, and GetGroup and UpdateGroup on it fail with InvalidRequestException."""
    xr = ctx.client("xray")
    name = ctx.unique_name("sim2real-behav-xray-grp-")[:32].rstrip("-")
    filter_expression = 'service("default")'
    created = xr.create_group(GroupName=name, FilterExpression=filter_expression)["Group"]
    ctx.on_cleanup(lambda: _delete_if_present(xr, name))
    arn_prefix = f"arn:aws:xray:{ctx.region}:{ctx.account}:group/{name}/"
    assert created.get("GroupARN", "").startswith(arn_prefix), (
        f"expected GroupARN to start with {arn_prefix!r}, got {created.get('GroupARN')!r}"
    )

    got = xr.get_group(GroupName=name)["Group"]
    assert got.get("FilterExpression") == filter_expression, (
        f"expected GetGroup FilterExpression {filter_expression!r}, got {got.get('FilterExpression')!r}"
    )
    assert name in _group_names(xr), "group missing after create"

    xr.delete_group(GroupName=name)

    assert name not in _group_names(xr), "group still listed after delete"

    # AWS's message names no id.
    error = _client_error(lambda: xr.get_group(GroupName=name))
    assert error.get("Code") == "InvalidRequestException", f"expected InvalidRequestException, got {error!r}"
    assert error.get("HTTPStatusCode") == 400, f"expected HTTP 400 from GetGroup, got {error!r}"
    expected_message = "Group not found"
    assert error.get("Message") == expected_message, f'expected the message {expected_message!r}, got {error.get("Message")!r}'

    # a mutation on the dead id fails the same way -- deletion is not just invisible to reads
    update_error = _client_error(
        lambda: xr.update_group(GroupName=name, FilterExpression='service("post-delete")')
    )
    assert update_error.get("Code") == "InvalidRequestException", f"expected InvalidRequestException, got {update_error!r}"
    assert update_error.get("HTTPStatusCode") == 400, f"expected HTTP 400 from UpdateGroup, got {update_error!r}"
    expected_message = "Group not found"
    assert update_error.get("Message") == expected_message, f'expected the message {expected_message!r}, got {update_error.get("Message")!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
