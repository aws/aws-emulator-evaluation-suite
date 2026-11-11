"""create-group-empty-filter-expression-persists."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-group-empty-filter-expression-persists"
GROUP = "representation"
SERVICES = ["xray"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGroup rejects an empty and an omitted FilterExpression alike with
    InvalidRequestException "Filter Expression is empty" and creates neither group, while a
    non-empty expression round-trips verbatim through CreateGroup and GetGroup."""
    xray = ctx.client("xray")

    explicit_name = ctx.unique_name("sim2real-xr-expl-")
    omitted_name = ctx.unique_name("sim2real-xr-omit-")
    real_name = ctx.unique_name("sim2real-xr-real-")

    # An explicit empty string is rejected, not silently persisted as an empty value.
    explicit = _client_error(
        lambda: xray.create_group(GroupName=explicit_name, FilterExpression="")
    )
    assert explicit.get("Code") == "InvalidRequestException", f"expected rejection, got {explicit!r}"
    assert explicit.get("Message") == "Filter Expression is empty", f"expected rejection, got {explicit!r}"

    # Omitting FilterExpression entirely is rejected the same way -- there is no reserved
    # catch-all default a caller can rely on by leaving it out.
    omitted = _client_error(lambda: xray.create_group(GroupName=omitted_name))
    assert omitted.get("Code") == "InvalidRequestException", f"expected rejection, got {omitted!r}"
    assert omitted.get("Message") == "Filter Expression is empty", f"expected rejection, got {omitted!r}"

    # Neither call created a group: GetGroup on either name now fails to find it.
    explicit_get = _client_error(lambda: xray.get_group(GroupName=explicit_name))
    assert (explicit_get.get("Code"), explicit_get.get("Message")) == (
        "InvalidRequestException", "Group not found"
    ), f"expected the rejected explicit-empty-filter group to be absent, got {explicit_get!r}"
    omitted_get = _client_error(lambda: xray.get_group(GroupName=omitted_name))
    assert (omitted_get.get("Code"), omitted_get.get("Message")) == (
        "InvalidRequestException", "Group not found"
    ), f"expected the rejected omitted-filter group to be absent, got {omitted_get!r}"

    # Positive control, exercising the same CreateGroup/GetGroup pair with a real, syntactically
    # rich filter expression: it persists exactly, character-for-character.
    real_filter = 'service("sim2real-probe") { fault OR error } AND http.url CONTAINS "/api?x=1&y=2"'
    created = xray.create_group(
        GroupName=real_name,
        FilterExpression=real_filter,
        Tags=[{"Key": "sim2real-check", "Value": "create-group-empty-filter-expression-persists"}],
    )["Group"]
    ctx.on_cleanup(lambda: xray.delete_group(GroupName=real_name))
    assert created["FilterExpression"] == real_filter, (
        f"expected CreateGroup to persist {real_filter!r} verbatim, got {created['FilterExpression']!r}"
    )

    fetched = xray.get_group(GroupName=real_name)["Group"]
    assert fetched["FilterExpression"] == real_filter, (
        f"expected GetGroup to read back {real_filter!r} verbatim, got {fetched['FilterExpression']!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

