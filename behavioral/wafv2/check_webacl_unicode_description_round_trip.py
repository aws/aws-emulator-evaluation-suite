"""webacl-unicode-description-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webacl-unicode-description-round-trip"
GROUP = "representation"
SERVICES = ["wafv2"]

# AWS WAF's Description pattern (`^[\w+=:#@/\-,\.][\w+=:#@/\-,\.\s]+[\w+=:#@/\-,\.]$`)
# is empirically ASCII-only: Java's default `\w`/`\s` character classes do not
# match multi-byte code points, so a *literal* multi-byte-unicode description is
# rejected server-side (see the negative case below). What IS representable and
# must round-trip byte-for-byte is a description built from every non-`\w`
# character class the pattern explicitly allows (`+ = : # @ / - , .` and an
# embedded space), bookended with a word character as the anchors require.
DESCRIPTION = "d1_permitted+=:#@/-,. chars_end"
_DESCRIPTION_PATTERN = r"^[\w+=:#@/\-,\.][\w+=:#@/\-,\.\s]+[\w+=:#@/\-,\.]$"

# A description containing multi-byte unicode (CJK ideographs + an accented
# Latin letter) is NOT representable -- AWS WAF rejects it server-side rather
# than accepting and silently mangling/truncating it.
UNICODE_DESCRIPTION = "WebACL_test_\u65e5\u672c\u8a9e_caf\u00e9_description_end"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Description using every allowed punctuation/space character round-trips unchanged
    through CreateWebACL and GetWebACL; one with multi-byte unicode, outside the documented
    pattern, is rejected with ValidationException rather than accepted or mangled."""
    wafv2 = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-webacl-uni-")
    resp = wafv2.create_web_acl(
        Name=name,
        Scope="REGIONAL",
        Description=DESCRIPTION,
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": name,
        },
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    summary = resp["Summary"]
    web_acl_id = summary["Id"]

    def _cleanup():
        try:
            current = wafv2.get_web_acl(Name=name, Scope="REGIONAL", Id=web_acl_id)
            wafv2.delete_web_acl(
                Name=name, Scope="REGIONAL", Id=web_acl_id, LockToken=current["LockToken"]
            )
            wafv2.get_web_acl(Name=name, Scope="REGIONAL", Id=web_acl_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise
        else:
            raise AssertionError("deleted WebACL is still readable via GetWebACL")

    ctx.on_cleanup(_cleanup)

    assert summary["Description"] == DESCRIPTION, summary["Description"]

    got = wafv2.get_web_acl(Name=name, Scope="REGIONAL", Id=web_acl_id)["WebACL"]
    assert got["Description"] == DESCRIPTION, got["Description"]

    # Overly-permissive boundary: a description outside the allowed character
    # class must be REJECTED, not silently accepted/mangled.
    other_name = ctx.unique_name("sim2real-webacl-uni-rej-")
    leaked = None
    try:
        leaked = wafv2.create_web_acl(
            Name=other_name,
            Scope="REGIONAL",
            Description=UNICODE_DESCRIPTION,
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": other_name,
            },
            Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
        )
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "ValidationException", exc.response["Error"]
        assert exc.response["Error"]["Message"] == (
            f"1 validation error detected: Value '{UNICODE_DESCRIPTION}' at 'description' "
            f"failed to satisfy constraint: Member must satisfy regular expression pattern: "
            f"{_DESCRIPTION_PATTERN}"
        ), exc.response["Error"]
    else:
        # If the service accepted it, clean up the actual
        # leaked resource by its real id (not a blind empty-id probe), then
        # fail loudly -- acceptance is the bug this check exists to catch.
        leaked_id = leaked["Summary"]["Id"]
        current = wafv2.get_web_acl(Name=other_name, Scope="REGIONAL", Id=leaked_id)
        wafv2.delete_web_acl(
            Name=other_name, Scope="REGIONAL", Id=leaked_id, LockToken=current["LockToken"]
        )
        raise AssertionError(
            "CreateWebACL accepted a Description outside the documented "
            "ASCII-only pattern instead of rejecting it with ValidationException"
        )

    # Effect absent: no WebACL with the rejected name exists anywhere in the
    # scope -- the rejected create must not have landed as a side effect.
    all_names = set()
    next_marker = None
    while True:
        kwargs = {"Scope": "REGIONAL"}
        if next_marker:
            kwargs["NextMarker"] = next_marker
        page = wafv2.list_web_acls(**kwargs)
        all_names.update(s["Name"] for s in page["WebACLs"])
        next_marker = page.get("NextMarker")
        if not next_marker:
            break
    assert other_name not in all_names, "a WebACL was created despite the rejected Description"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

