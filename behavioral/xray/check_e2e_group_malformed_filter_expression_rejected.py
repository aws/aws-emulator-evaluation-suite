"""e2e-group-malformed-filter-expression-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "e2e-group-malformed-filter-expression-rejected"
GROUP = "e2e"
SERVICES = ["xray"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGroup rejects a syntactically malformed FilterExpression with InvalidRequestException,
    creates no group under that name, while a group with a valid FilterExpression in the same
    call shape still succeeds."""
    xray = ctx.client("xray")
    bad_name = ctx.unique_name("sim2real-badgrp-")[:32]
    good_name = ctx.unique_name("sim2real-goodgrp-")[:32]

    def _bad_call():
        return xray.create_group(
            GroupName=bad_name,
            FilterExpression='annotation.marker === "x" AND AND (((',
        )

    error = _client_error(ctx, bad_name, _bad_call)
    assert error.get("Code") == "InvalidRequestException", (
        f"a syntactically malformed FilterExpression must be refused with "
        f"InvalidRequestException, got {error!r}"
    )
    assert error.get("Message") == "Error Location: line 1, position 20 : Invalid input symbol: '='", (
        f"the refusal must locate the syntax error, got {error!r}"
    )

    names_after_failure = _all_group_names(xray)
    assert bad_name not in names_after_failure, (
        f"CreateGroup was refused but {bad_name!r} exists anyway: {sorted(names_after_failure)!r}"
    )

    good_filter = 'annotation.marker = "ok"'
    xray.create_group(GroupName=good_name, FilterExpression=good_filter)
    ctx.on_cleanup(lambda: _delete_group_if_present(xray, good_name))

    group = xray.get_group(GroupName=good_name)["Group"]
    assert group["FilterExpression"] == good_filter, (
        f"GetGroup must echo the syntactically valid FilterExpression verbatim; "
        f"expected {good_filter!r}, got {group['FilterExpression']!r}"
    )


# ===== helpers =====

def _client_error(ctx, created_name, fn):
    """The refusal's Error dict. Raises on unexpected SUCCESS rather than returning a falsy
    sentinel, so an over-permissive target fails on its acceptance, not on a code mismatch; if it
    does succeed, cleanup is registered from the response before raising so the leak this
    check's own assertion caught does not also survive it."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    ctx.on_cleanup(lambda: _delete_group_if_present(ctx.client("xray"), created_name))
    raise AssertionError(
        f"expected CreateGroup to be refused for a malformed FilterExpression, but it "
        f"succeeded: {result!r}"
    )


def _all_group_names(xray) -> set:
    names = set()
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = xray.get_groups(**kwargs)
        names.update(g["GroupName"] for g in resp.get("Groups", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return names


def _delete_group_if_present(xray, group_name: str) -> None:
    """Teardown: a group that is already gone is clean; any other refusal is a failure."""
    from botocore.exceptions import ClientError

    try:
        xray.delete_group(GroupName=group_name)
    except ClientError as e:
        err = e.response.get("Error", {})
        if (err.get("Code"), err.get("Message")) != ("InvalidRequestException", "Group not found"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
