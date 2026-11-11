"""op-contract-create-group."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-create-group"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGroup: success-path returns a Group with the requested name, default Path,
    and a well-formed Arn; error boundary is EntityAlreadyExistsException for a duplicate
    GroupName."""
    iam = ctx.client("iam")

    group_name = ctx.unique_name("sim2real-group-")
    created = iam.create_group(GroupName=group_name)["Group"]
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group_name))

    assert created["GroupName"] == group_name, (
        f"CreateGroup echoed GroupName={created['GroupName']!r}, expected {group_name!r}"
    )
    assert created["Path"] == "/", f"expected default Path '/', got {created['Path']!r}"
    assert created["Arn"].endswith(f":group/{group_name}"), (
        f"Arn {created['Arn']!r} does not end with :group/{group_name}"
    )

    fetched = iam.get_group(GroupName=group_name)["Group"]
    assert fetched["GroupName"] == group_name, (
        f"GetGroup GroupName {fetched['GroupName']!r} != {group_name!r}"
    )
    assert fetched["GroupId"] == created["GroupId"], (
        f"GetGroup id {fetched['GroupId']!r} != CreateGroup id {created['GroupId']!r}"
    )

    # A different Path on the duplicate attempt: an upsert-style emulator that accepts the
    # duplicate as a silent update would leak through here even though the id equality check
    # above cannot detect it (the id never changes on an in-place update).
    code, message = _error(
        lambda: iam.create_group(GroupName=group_name, Path="/should-not-apply/")
    )
    assert code == "EntityAlreadyExists", f"expected EntityAlreadyExists for duplicate GroupName, got {code}"
    expected = f"Group with name {group_name} already exists."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unaffected = iam.get_group(GroupName=group_name)["Group"]
    assert unaffected["GroupId"] == created["GroupId"], (
        f"rejected duplicate create must not replace the original: id was "
        f"{created['GroupId']!r}, now {unaffected['GroupId']!r}"
    )
    assert unaffected["Path"] == "/", (
        f"rejected duplicate create (Path='/should-not-apply/') must not change the original's "
        f"path: now {unaffected['Path']!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
