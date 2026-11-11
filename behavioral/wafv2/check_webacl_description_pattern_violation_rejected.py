"""webacl-description-pattern-violation-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webacl-description-pattern-violation-rejected"
GROUP = "representation"
SERVICES = ["wafv2"]

BAD_DESCRIPTION = "invalid!description"
_DESCRIPTION_PATTERN = r"^[\w+=:#@/\-,\.][\w+=:#@/\-,\.\s]+[\w+=:#@/\-,\.]$"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWebACL with a Description outside the documented pattern fails with ValidationException and
    the exact pattern message and lists no web ACL; a pattern-valid Description is created and read
    back.
    """
    wafv2 = ctx.client("wafv2")
    scope = "REGIONAL"
    bad_name = ctx.unique_name("sim2real-baddesc-")
    good_name = ctx.unique_name("sim2real-gooddesc-")

    def _visibility(n: str) -> dict:
        return {
            "SampledRequestsEnabled": False,
            "CloudWatchMetricsEnabled": False,
            "MetricName": n.replace("-", "_"),
        }

    def _attempt_create_bad():
        return wafv2.create_web_acl(
            Name=bad_name,
            Scope=scope,
            DefaultAction={"Allow": {}},
            VisibilityConfig=_visibility(bad_name),
            Description=BAD_DESCRIPTION,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )

    error = None
    leaked_id = None
    try:
        leaked = _attempt_create_bad()
        leaked_id = leaked["Summary"]["Id"]
    except ClientError as exc:
        error = exc.response["Error"]

    if leaked_id is not None:
        current = wafv2.get_web_acl(Name=bad_name, Scope=scope, Id=leaked_id)
        wafv2.delete_web_acl(
            Name=bad_name, Scope=scope, Id=leaked_id, LockToken=current["LockToken"]
        )
        raise AssertionError(
            f"expected ValidationException for Description containing '!', "
            f"but create succeeded with Description={current['WebACL'].get('Description')!r}"
        )
    assert error["Code"] == "ValidationException", f"error={error!r}"
    assert error["Message"] == (
        f"1 validation error detected: Value '{BAD_DESCRIPTION}' at 'description' failed to "
        f"satisfy constraint: Member must satisfy regular expression pattern: {_DESCRIPTION_PATTERN}"
    ), f"unexpected message: {error['Message']!r}"

    # Effect absent: no WebACL with the rejected name exists anywhere in the scope.
    all_names = set()
    next_marker = None
    while True:
        kwargs = {"Scope": scope}
        if next_marker:
            kwargs["NextMarker"] = next_marker
        page = wafv2.list_web_acls(**kwargs)
        for summary in page["WebACLs"]:
            all_names.add(summary["Name"])
        next_marker = page.get("NextMarker")
        if not next_marker:
            break
    assert bad_name not in all_names, "a WebACL was created despite the rejected Description"

    # Positive control: a pattern-valid description of the same general shape succeeds.
    created = wafv2.create_web_acl(
        Name=good_name,
        Scope=scope,
        DefaultAction={"Allow": {}},
        VisibilityConfig=_visibility(good_name),
        Description="a-valid-description",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    good_id = created["Summary"]["Id"]

    def _cleanup():
        current = wafv2.get_web_acl(Name=good_name, Scope=scope, Id=good_id)
        wafv2.delete_web_acl(
            Name=good_name, Scope=scope, Id=good_id, LockToken=current["LockToken"]
        )

    ctx.on_cleanup(_cleanup)

    after_create = wafv2.get_web_acl(Name=good_name, Scope=scope, Id=good_id)
    assert after_create["WebACL"]["Description"] == "a-valid-description", (
        f"expected Description='a-valid-description', "
        f"got {after_create['WebACL'].get('Description')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
