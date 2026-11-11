"""regexpatternset-invalid-syntax-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "regexpatternset-invalid-syntax-rejected"
GROUP = "representation"
SERVICES = ["wafv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRegexPatternSet with a syntactically invalid regular expression is rejected
    with WAFInvalidParameterException, no set is created under that name, and a
    subsequent create with valid syntax (the positive control) succeeds normally."""
    wafv2 = ctx.client("wafv2")
    scope = "REGIONAL"
    name = ctx.unique_name("sim2real-behav-regex-bad-")

    code, message = _error(lambda: wafv2.create_regex_pattern_set(
        Name=name, Scope=scope, RegularExpressionList=[{"RegexString": "(unterminated["}],
    ))
    assert code == "WAFInvalidParameterException", (
        f"expected WAFInvalidParameterException for a syntactically invalid regex, got {code!r}"
    )
    assert message == (
        "Error reason: The parameter contains formatting that is not valid., "
        "field: REGEX_PATTERN_SET, parameter: (unterminated["
    ), message

    listing = wafv2.list_regex_pattern_sets(Scope=scope)["RegexPatternSets"]
    matches = [s["Name"] for s in listing if s["Name"] == name]
    assert not matches, f"rejected create must not leave a set behind, found {matches!r}"

    # Positive control: the same name with a syntactically valid pattern must succeed.
    created = wafv2.create_regex_pattern_set(
        Name=name, Scope=scope, RegularExpressionList=[{"RegexString": "^[a-z]+$"}],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    set_id = created["Summary"]["Id"]
    ctx.on_cleanup(lambda: wafv2.delete_regex_pattern_set(
        Name=name, Scope=scope, Id=set_id,
        LockToken=wafv2.get_regex_pattern_set(Name=name, Scope=scope, Id=set_id)["LockToken"],
    ))

    got = wafv2.get_regex_pattern_set(Name=name, Scope=scope, Id=set_id)
    stored = got["RegexPatternSet"]["RegularExpressionList"]
    assert stored == [{"RegexString": "^[a-z]+$"}], (
        f"positive control must round-trip the valid pattern verbatim, got {stored!r}"
    )


def _error(fn):
    """Return (code, message) of the ClientError fn raises. A call that succeeds raises
    AssertionError: the caller expects a refusal."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
