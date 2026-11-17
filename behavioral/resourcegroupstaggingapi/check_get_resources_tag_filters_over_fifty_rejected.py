"""get-resources-tag-filters-over-fifty-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-resources-tag-filters-over-fifty-rejected"
GROUP = "validation"
SERVICES = ["resourcegroupstaggingapi"]


def _error(fn):
    """The (Error.Code, Error.Message) ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResources refuses more than 50 TagFilters with ValidationException naming the
    submitted list, while exactly 50 is accepted and returns an empty mapping."""
    rgta = ctx.client("resourcegroupstaggingapi")
    base = ctx.unique_name("sim2real-behav-rgta-ov-")
    over_limit = [
        {"Key": f"{base}-{i}", "Values": [f"{base}-val-{i}"]} for i in range(51)
    ]
    at_limit = over_limit[:50]

    expected_message = (
        "1 validation error detected: Value '["
        + ", ".join(
            f"TagFilter(key={f['Key']}, values=[{f['Values'][0]}])" for f in over_limit
        )
        + "]' at 'tagFilters' failed to satisfy constraint: "
        "Member must have length less than or equal to 50"
    )
    code, message = _error(lambda: rgta.get_resources(TagFilters=over_limit))
    assert code == "ValidationException", f"51 TagFilters: expected ValidationException, got {code!r}"
    assert message == expected_message, (
        f"51 TagFilters: unexpected message\nexpected: {expected_message!r}\ngot:      {message!r}"
    )

    # Positive control: the legal neighbour, exactly at the limit, succeeds.
    resp = rgta.get_resources(TagFilters=at_limit)
    assert resp["PaginationToken"] == "", (
        f"50 TagFilters: expected an empty PaginationToken, got {resp['PaginationToken']!r}"
    )
    assert resp["ResourceTagMappingList"] == [], (
        f"50 TagFilters: expected no matches, got {resp['ResourceTagMappingList']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
