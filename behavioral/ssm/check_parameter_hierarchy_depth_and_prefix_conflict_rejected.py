"""parameter-hierarchy-depth-and-prefix-conflict-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "parameter-hierarchy-depth-and-prefix-conflict-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ssm']


def _error(fn):
    """Return the (code, message) of the ClientError fn raises; raise if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"the call was expected to be refused but it succeeded: {result!r}")


def _param_name(ctx, suffix=""):
    # SSM requires a leading '/' for any hierarchical (slash-containing) name.
    return "/" + ctx.unique_name("sim2real-behav-" + suffix)


def _call_with_retry(fn, retries=10, delay=2.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") in (
                "TooManyUpdates",
                "ThrottlingException",
            ):
                time.sleep(delay)
                continue
            raise
    raise last


def _delete_parameter_idempotent(ssm, name):
    """Delete one parameter, retrying TooManyUpdates and treating ParameterNotFound as success.

    A delete racing the check's own Overwrite would otherwise leak; `leaf` is deleted by run()."""
    def _delete():
        try:
            ssm.delete_parameter(Name=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ParameterNotFound":
                return None
            raise
        return None

    _call_with_retry(_delete)


def _track_parameter(ctx, ssm, name):
    ctx.on_cleanup(lambda: _delete_parameter_idempotent(ssm, name))
    return name


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Names allow 16 segments (15 levels plus the leaf), and a name may be both leaf and level.

    Depth, trailing slash, unqualified and reserved /aws/ names are refused with distinct errors.

    Reference: https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-hierarchies.html
    """

    ssm = ctx.client("ssm")

    root = _param_name(ctx, "hier-")

    # --- depth limit: 16 slash-separated segments is legal, 17 is not --------
    # The leaf is not a level: 16 segments is 15 levels plus the leaf, so both sides are asserted.
    deepest_legal = root + "".join(f"/l{i}" for i in range(2, 17))
    assert deepest_legal.count("/") == 16, f"test setup wrong: {deepest_legal}"
    _track_parameter(ctx, ssm, deepest_legal)
    ok = ssm.put_parameter(Name=deepest_legal, Value="16-segments-is-legal", Type="String")
    assert ok["Version"] == 1, (
        f"16 slash-separated segments is 15 levels plus the leaf and must be accepted, got {ok}"
    )

    one_too_deep = deepest_legal + "/l17"
    assert one_too_deep.count("/") == 17, f"test setup wrong: {one_too_deep}"
    too_deep = None
    too_deep_msg = None
    try:
        ssm.put_parameter(Name=one_too_deep, Value="17-segments-is-illegal", Type="String")
    except ClientError as exc:
        too_deep = exc.response.get("Error", {}).get("Code")
        too_deep_msg = exc.response.get("Error", {}).get("Message") or ""
    assert too_deep == "HierarchyLevelLimitExceededException", (
        "17 slash-separated segments exceeds the hierarchy depth limit and must be refused with "
        f"HierarchyLevelLimitExceededException, got {too_deep!r}"
    )
    # The diagnostic states the limit as a level count, not a segment count.
    assert too_deep_msg == "Depth of the tree cannot exceed 15", (
        f"unexpected depth-limit diagnostic: {too_deep_msg!r}"
    )
    # Effect absent: the rejected 17th segment must not exist.
    assert _error(lambda: ssm.get_parameter(Name=one_too_deep)) == ("ParameterNotFound", ""), (
        f"a rejected PutParameter must not create {one_too_deep}"
    )
    # Control: the rejection did not disturb the accepted, maximally-deep parameter.
    assert (
        ssm.get_parameter(Name=deepest_legal)["Parameter"]["Value"] == "16-segments-is-legal"
    ), "the depth rejection must leave the accepted 16-segment parameter intact"

    # --- a name may be BOTH a leaf and a level, in either creation order -----
    # Parameter Store does not enforce leaf/level exclusivity: /x and /x/child coexist, created in
    # either order; HierarchyTypeMismatchException is not raised for this.
    leaf = _param_name(ctx, "leaf-")
    _track_parameter(ctx, ssm, leaf)
    ssm.put_parameter(Name=leaf, Value="i-am-a-leaf", Type="String")

    child = leaf + "/child"
    _track_parameter(ctx, ssm, child)
    nested = ssm.put_parameter(Name=child, Value="i-am-a-child", Type="String")
    assert nested["Version"] == 1, (
        f"a parameter nested under an existing leaf is accepted by real AWS, got {nested}"
    )
    # And the reverse order: the child first, then the parent name as a leaf of its own.
    rev_root = _param_name(ctx, "rev-")
    rev_child = rev_root + "/child"
    _track_parameter(ctx, ssm, rev_child)
    ssm.put_parameter(Name=rev_child, Value="child-first", Type="String")
    _track_parameter(ctx, ssm, rev_root)
    rev = ssm.put_parameter(Name=rev_root, Value="parent-second", Type="String")
    assert rev["Version"] == 1, (
        f"an interior path may also be created as a leaf afterwards, got {rev}"
    )

    # Both coexist and neither shadows the other.
    assert ssm.get_parameter(Name=leaf)["Parameter"]["Value"] == "i-am-a-leaf", (
        "the nested write must not have overwritten the leaf at the same prefix"
    )
    assert ssm.get_parameter(Name=child)["Parameter"]["Value"] == "i-am-a-child", (
        "the nested parameter must be readable by its own name"
    )
    assert ssm.get_parameter(Name=rev_root)["Parameter"]["Value"] == "parent-second", rev_root
    assert ssm.get_parameter(Name=rev_child)["Parameter"]["Value"] == "child-first", rev_child

    # A path read at the shared prefix returns the descendants only, never the leaf at that name.
    beneath = ssm.get_parameters_by_path(Path=leaf, Recursive=True)["Parameters"]
    assert [p["Name"] for p in beneath] == [child], (
        f"a path read must return the descendants of {leaf} and NOT the leaf stored at that "
        f"exact name, got {[p['Name'] for p in beneath]}"
    )

    # Deleting the leaf leaves the descendant untouched: they are independent entries, not a tree.
    ssm.delete_parameter(Name=leaf)
    assert _error(lambda: ssm.get_parameter(Name=leaf)) == ("ParameterNotFound", ""), leaf
    assert ssm.get_parameter(Name=child)["Parameter"]["Value"] == "i-am-a-child", (
        "deleting the leaf at a prefix must not delete what is stored beneath it"
    )
    bumped = _call_with_retry(
        lambda: ssm.put_parameter(
            Name=child, Value="still-writable", Type="String", Overwrite=True
        )
    )
    assert bumped["Version"] == 2, (
        f"the surviving nested parameter must remain writable, got {bumped}"
    )

    # --- the name rules real AWS DOES enforce, as distinguishable diagnostics -
    # Together with the depth limit these give three distinct error codes and four messages.
    reserved = "/aws/" + ctx.unique_name("sim2real-behav-reserved-")
    refusals = {}
    for label, name, expected_code, expected_msg in (
        (
            "trailing slash",
            leaf + "/",
            "ValidationException",
            "Parameter name must not end with slash.",
        ),
        (
            "not fully qualified",
            _param_name(ctx, "unqualified-").lstrip("/") + "/child",
            "ValidationException",
            "Parameter name must be a fully qualified name.",
        ),
        (
            "reserved /aws/ namespace",
            reserved,
            "AccessDeniedException",
            f"No access to reserved parameter name: {reserved.lstrip('/')}.",
        ),
    ):
        code = None
        msg = None
        try:
            ssm.put_parameter(Name=name, Value="must-not-exist", Type="String")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = exc.response.get("Error", {}).get("Message") or ""
        assert code == expected_code, (
            f"a {label} parameter name ({name!r}) must be refused with {expected_code}, got "
            f"{code!r}: {msg!r}"
        )
        assert msg == expected_msg, (
            f"unexpected {label} diagnostic: {msg!r} (expected {expected_msg!r})"
        )
        refusals[label] = (code, msg)

    codes = {too_deep} | {c for c, _ in refusals.values()}
    assert len(codes) == 3, (
        f"the depth limit, the malformed-name rules and the reserved namespace must be three "
        f"distinct error codes, got {sorted(codes)}"
    )
    msgs = [too_deep_msg] + [m for _, m in refusals.values()]
    assert len(set(msgs)) == len(msgs), (
        f"four distinct name defects produced indistinguishable diagnostics: {msgs}"
    )
    # The read is gated like the write (AccessDeniedException, not ParameterNotFound), so the
    # reserved namespace leaks no existence.
    reserved_read = None
    reserved_read_msg = None
    try:
        ssm.get_parameter(Name=reserved)
    except ClientError as exc:
        reserved_read = exc.response.get("Error", {}).get("Code")
        reserved_read_msg = exc.response.get("Error", {}).get("Message") or ""
    assert reserved_read == "AccessDeniedException", (
        f"reading the reserved name {reserved} must be refused with AccessDeniedException (not "
        f"ParameterNotFound -- the namespace is gated, not empty), got {reserved_read!r}"
    )
    assert reserved_read_msg == refusals["reserved /aws/ namespace"][1], (
        f"the reserved-namespace read and write must give the same diagnostic, got "
        f"{reserved_read_msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
