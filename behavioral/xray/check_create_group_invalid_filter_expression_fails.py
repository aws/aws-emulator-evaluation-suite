"""create-group-invalid-filter-expression-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-group-invalid-filter-expression-fails"
GROUP = 'overly-permissive'
SERVICES = ['xray']


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGroup refuses a malformed FilterExpression with InvalidRequestException naming the
    error location and creates no group, while a valid expression in the same run is created."""
    xr = ctx.client("xray")
    name = ctx.unique_name("sim2real-behav-xray-grp-")[:32].rstrip("-")
    error = _client_error(
        lambda: xr.create_group(GroupName=name, FilterExpression="this is (not a valid filter")
    )
    assert error.get("Code") == "InvalidRequestException", (
        f"expected InvalidRequestException, got {error!r}"
    )
    assert error.get("Message") == "Error Location: line 1, position 1 : Invalid input symbol: 'thi'", (
        f"the refusal must locate the syntax error, got {error!r}"
    )

    missing = _client_error(lambda: xr.get_group(GroupName=name))
    assert (missing.get("Code"), missing.get("Message")) == (
        "InvalidRequestException", "Group not found"
    ), f"group should not exist after rejected create, got {missing!r}"

    # Positive control: a syntactically valid FilterExpression, in the same run, still succeeds --
    # without this, "rejects garbage" is indistinguishable from "rejects every CreateGroup".
    good_name = ctx.unique_name("sim2real-behav-xray-grp-")[:32].rstrip("-")
    good_filter = 'service("sim2real-behav-xray")'
    created = xr.create_group(GroupName=good_name, FilterExpression=good_filter)
    ctx.on_cleanup(lambda: xr.delete_group(GroupName=good_name))
    assert created["Group"]["FilterExpression"] == good_filter, created

    fetched = xr.get_group(GroupName=good_name)["Group"]
    assert fetched["GroupName"] == good_name, fetched


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
