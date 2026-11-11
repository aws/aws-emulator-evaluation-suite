"""op-contract-list-groups."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-list-groups"
GROUP = "error-semantics"
SERVICES = ["iam"]

_PATH_PREFIX_MESSAGE = (
    "The specified value for pathPrefix is invalid. It must begin with the / character and "
    "contain only alphanumeric characters and/or / characters."
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListGroups surfaces a freshly created group; malformed PathPrefix -> ValidationError."""
    iam = ctx.client("iam")

    group_name = ctx.unique_name("sim2real-behav-group-")
    created = iam.create_group(GroupName=group_name)["Group"]
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group_name))

    groups = _list_all(iam.list_groups, "Groups")
    match = next((g for g in groups if g["GroupName"] == group_name), None)
    assert match is not None, f"{group_name} not found in ListGroups output"
    assert match["Arn"] == created["Arn"], f"expected Arn {created['Arn']!r}, got {match['Arn']!r}"
    assert match["GroupId"] == created["GroupId"], (
        f"expected GroupId {created['GroupId']!r}, got {match['GroupId']!r}"
    )
    assert "CreateDate" in match, f"expected CreateDate in ListGroups entry, got keys {sorted(match)}"

    # PathPrefix must begin with "/" -- an invalid one is a service-side validation boundary.
    code, message = _error(lambda: iam.list_groups(PathPrefix="badpath"))
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    assert message == _PATH_PREFIX_MESSAGE, f"expected message {_PATH_PREFIX_MESSAGE!r}, got {message!r}"


def _list_all(fn, list_key, **kwargs):
    items = []
    marker = None
    while True:
        params = dict(kwargs)
        if marker:
            params["Marker"] = marker
        resp = fn(**params)
        items.extend(resp.get(list_key, []))
        if not resp.get("IsTruncated"):
            break
        marker = resp.get("Marker")
    return items


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
