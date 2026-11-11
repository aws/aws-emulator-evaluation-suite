"""regexpatternset-unicode-pattern-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "regexpatternset-unicode-pattern-round-trip"
GROUP = "representation"
SERVICES = ["wafv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A regex pattern containing non-ASCII/unicode literals survives CreateRegexPatternSet,
    GetRegexPatternSet, and UpdateRegexPatternSet with exact byte equality -- no
    transliteration, normalization, or truncation of the unicode characters."""
    wafv2 = ctx.client("wafv2")
    scope = "REGIONAL"
    name = ctx.unique_name("sim2real-behav-regex-uni-")

    pattern1 = "café-\\d{2,4}-\u65e5\u672c\u8a9e-\u03a9"  # "café-<digits>-日本語-Ω"

    created = wafv2.create_regex_pattern_set(
        Name=name, Scope=scope, RegularExpressionList=[{"RegexString": pattern1}],
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:check", "Value": CHECK},
        ],
    )
    set_id = created["Summary"]["Id"]
    ctx.on_cleanup(lambda: wafv2.delete_regex_pattern_set(
        Name=name, Scope=scope, Id=set_id,
        LockToken=wafv2.get_regex_pattern_set(Name=name, Scope=scope, Id=set_id)["LockToken"],
    ))

    got = wafv2.get_regex_pattern_set(Name=name, Scope=scope, Id=set_id)
    actual1 = got["RegexPatternSet"]["RegularExpressionList"]
    assert actual1 == [{"RegexString": pattern1}], (
        f"expected the created unicode pattern preserved byte-for-byte, got {actual1!r}"
    )

    pattern2 = "m\u00fcnchen-[\u0391-\u03a9]+"  # "münchen-[Α-Ω]+"
    wafv2.update_regex_pattern_set(
        Name=name,
        Scope=scope,
        Id=set_id,
        RegularExpressionList=[{"RegexString": pattern1}, {"RegexString": pattern2}],
        LockToken=got["LockToken"],
    )

    got2 = wafv2.get_regex_pattern_set(Name=name, Scope=scope, Id=set_id)
    actual2 = got2["RegexPatternSet"]["RegularExpressionList"]
    expected2 = [{"RegexString": pattern1}, {"RegexString": pattern2}]
    assert actual2 == expected2, (
        f"expected {expected2!r} after update, got {actual2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
