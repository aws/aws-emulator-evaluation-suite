"""create-filter-empty-criteria-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-filter-empty-criteria-rejected"
GROUP = "overly-permissive"
SERVICES = ["inspector2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFilter with an unsupported StringComparison operator in filterCriteria fails with
    ValidationException and its exact message and creates nothing, while a valid filter is
    created and listed."""
    inspector2 = ctx.client("inspector2")
    bad_name = ctx.unique_name("sim2real-filter-empty-")
    good_name = ctx.unique_name("sim2real-filter-good-")

    code, message = _error(
        lambda: inspector2.create_filter(
            action="NONE",
            name=bad_name,
            filterCriteria={"severity": [{"comparison": "NOT_A_REAL_COMPARISON", "value": "HIGH"}]},
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException, got {code!r}"
    )
    expected_message = (
        "1 validation error detected: Value at 'filterCriteria.severity.1.member.comparison' failed to "
        "satisfy constraint: Member must satisfy enum value set: [NOT_EQUALS, PREFIX, EQUALS]"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no filter with the rejected name was created.
    names = {f["name"] for f in _all_filters(inspector2)}
    assert bad_name not in names, "filter with an invalid comparison operator was created despite rejection"

    # Positive control: a filter with real criteria is created successfully in the same file.
    created = inspector2.create_filter(
        action="NONE",
        name=good_name,
        filterCriteria={"severity": [{"comparison": "EQUALS", "value": "HIGH"}]},
    )
    ctx.on_cleanup(lambda: inspector2.delete_filter(arn=created["arn"]))
    names_after = {f["name"] for f in _all_filters(inspector2)}
    assert good_name in names_after, f"expected {good_name!r} in {names_after!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _all_filters(inspector2):
    items = []
    next_token = None
    while True:
        kwargs = {"maxResults": 50}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = inspector2.list_filters(**kwargs)
        items.extend(resp.get("filters", []))
        next_token = resp.get("nextToken")
        if not next_token:
            return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
