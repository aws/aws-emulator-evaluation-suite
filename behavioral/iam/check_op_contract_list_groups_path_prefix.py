"""op-contract-listGroups-path-prefix."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listGroups-path-prefix"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PathPrefix filtering returns exactly the groups under our unique path; a Marker IAM never issued is rejected."""
    iam = ctx.client("iam")
    suffix = ctx.unique_name("sim2real-batch09-grp")
    path = f"/{suffix}/"
    name_a = f"{suffix}-a"
    name_b = f"{suffix}-b"
    iam.create_group(GroupName=name_a, Path=path)
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=name_a))
    iam.create_group(GroupName=name_b, Path=path)
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=name_b))

    resp = iam.list_groups(PathPrefix=path)
    names = {g["GroupName"] for g in resp["Groups"]}
    assert names == {name_a, name_b}, f"expected exactly {{name_a, name_b}}, got {names}"
    for g in resp["Groups"]:
        assert g["Path"] == path

    # Error boundary: a Marker that was never issued by IAM is rejected, not silently accepted.
    # (MaxItems=0 cannot exercise this: botocore's own param validator rejects it before the
    # request leaves the SDK, so the target is never asked.)
    code, message = _error(lambda: iam.list_groups(Marker="not-a-real-continuation-token"))
    assert code == "ValidationError", f"unexpected error code {code}"
    assert message == "Invalid Marker.", f"expected message 'Invalid Marker.', got {message!r}"


def _error(fn):
    """(code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
