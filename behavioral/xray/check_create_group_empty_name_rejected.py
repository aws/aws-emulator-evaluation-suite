"""create-group-empty-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-group-empty-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["xray"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGroup with an empty-string GroupName is rejected by the service (GroupName
    length must be 1-32) rather than creating an unnamed group; a validly-named group in
    the same run still succeeds."""
    xray = ctx.client("xray")

    error = _client_error(
        lambda: _call_bypassing_param_validation(xray, "create_group", GroupName="")
    )
    assert error.get("Code") == "ValidationException", (
        f"expected an invalid-parameter rejection for empty GroupName, got {error!r}"
    )
    assert error.get("Message") == (
        "1 validation error detected: Value '' at 'groupName' failed to satisfy constraint: "
        "Member must have length greater than or equal to 1"
    ), f"the rejection must name the groupName length constraint, got {error!r}"

    groups = xray.get_groups()["Groups"]
    assert not any(g["GroupName"] == "" for g in groups), "an unnamed group must not exist"

    # positive control: a validly-named group in the same file still succeeds. Provide an
    # explicit (always-true) FilterExpression — an empty/absent one is itself rejected by
    # the service with its own InvalidRequestException ("Filter Expression is empty"),
    # which would be an unrelated failure mode for this check.
    group_name = ctx.unique_name("sim2real-behav-")
    xray.create_group(
        GroupName=group_name,
        FilterExpression="duration >= 0",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: xray.delete_group(GroupName=group_name))
    matching = [g for g in xray.get_groups()["Groups"] if g["GroupName"] == group_name]
    assert len(matching) == 1, f"expected exactly one group named {group_name!r} in GetGroups, found {matching!r}"


def _call_bypassing_param_validation(client, method_name: str, **kwargs):
    """boto3 rejects an empty GroupName client-side (the shape's min length of 1) before
    any request is ever sent, which would only exercise the SDK's own validator rather
    than the X-Ray service's own length check. botocore wraps the client's serializer in
    a ParamValidationDecorator when parameter_validation is enabled (the default); swap
    it out for its inner, unvalidated serializer for exactly this one call so the request
    actually reaches the server and exercises the server-side rejection the operation's
    error catalog documents (GroupName length outside 1-32 -> InvalidRequestException)."""
    serializer = client._serializer
    inner = getattr(serializer, "_serializer", None)
    if inner is None:
        return getattr(client, method_name)(**kwargs)
    client._serializer = inner
    try:
        return getattr(client, method_name)(**kwargs)
    finally:
        client._serializer = serializer


def _client_error(fn):
    """Call fn(); return its Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a rejection for empty GroupName, but CreateGroup SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
