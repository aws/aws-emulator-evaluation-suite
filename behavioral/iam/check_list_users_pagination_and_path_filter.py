"""op-contract-list-users."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-list-users"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListUsers: PathPrefix filtering + MaxItems/Marker pagination round-trip, and an invalid Marker boundary."""
    iam = ctx.client("iam")
    prefix = ctx.unique_name("sim2real-lu")
    path = f"/{prefix}/"

    created = []
    for i in range(3):
        name = ctx.unique_name(f"sim2real-lu-u{i}-")
        iam.create_user(UserName=name, Path=path, Tags=[{"Key": "sim2real", "Value": CHECK}])
        created.append(name)
        ctx.on_cleanup(lambda n=name: iam.delete_user(UserName=n))

    # Success path: PathPrefix filter returns exactly the users we created under this path.
    resp = iam.list_users(PathPrefix=path)
    found_names = {u["UserName"] for u in resp["Users"]}
    assert found_names == set(created), f"expected {created}, got {found_names}"
    for u in resp["Users"]:
        assert u["Path"] == path, f"expected path {path}, got {u['Path']}"
        assert u["UserName"] in u["Arn"], f"expected {u['UserName']!r} in arn {u['Arn']!r}"

    # Pagination: MaxItems=1 must truncate and expose a usable Marker.
    page1 = iam.list_users(PathPrefix=path, MaxItems=1)
    assert len(page1["Users"]) == 1, f"expected exactly 1 user, got {page1['Users']}"
    assert page1["IsTruncated"] is True, f"expected IsTruncated=True, got {page1['IsTruncated']!r}"
    assert "Marker" in page1, f"expected a Marker key in truncated response, got keys {list(page1)}"

    seen = {page1["Users"][0]["UserName"]}
    marker = page1["Marker"]
    is_truncated = True
    guard = 0
    while is_truncated and guard < 10:
        guard += 1
        page = iam.list_users(PathPrefix=path, MaxItems=1, Marker=marker)
        for u in page["Users"]:
            assert u["UserName"] not in seen, "pagination returned a duplicate user"
            seen.add(u["UserName"])
        is_truncated = page["IsTruncated"]
        marker = page.get("Marker")
    assert seen == set(created), f"pagination did not surface all users: {seen}"

    # Error boundary: a Marker that was never issued by IAM is rejected, not silently accepted.
    code, message = _error_code(lambda: iam.list_users(Marker="not-a-real-continuation-token"))
    assert code == "ValidationError", f"unexpected error code {code}"
    assert message == _BOGUS_MARKER_MESSAGE, (
        f"the bogus Marker must be refused with AWS's exact message {_BOGUS_MARKER_MESSAGE!r}; "
        f"got {message!r}"
    )


_BOGUS_MARKER_MESSAGE = "Invalid Marker."


def _error_code(fn):
    """``(code, message)`` of a call real AWS refuses; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS refuses this call, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
