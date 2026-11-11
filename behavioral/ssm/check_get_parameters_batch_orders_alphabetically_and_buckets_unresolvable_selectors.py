"""get-parameters-batch-orders-alphabetically-and-buckets-unresolvable-selectors."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-parameters-batch-orders-alphabetically-and-buckets-unresolvable-selectors"
GROUP = "representation"
SERVICES = ["ssm"]

_LABEL = "sim2real-batch-pin"
_THROTTLE = ("TooManyUpdates", "ThrottlingException", "Throttling")


def _error(fn):
    """Return the ClientError Error dict (Code and Message) raised by fn, or raise if it
    unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        "the call was expected to be refused but it succeeded; a falsy sentinel here "
        "would let an over-permissive target launder acceptance into a code mismatch"
    )


def _param_name(ctx, suffix=""):
    # SSM requires a leading '/' for any hierarchical (slash-containing) name.
    return "/" + ctx.unique_name("sim2real-behav-" + suffix)


def _call_with_retry(fn, retries=15, delay=2.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") in _THROTTLE:
                time.sleep(delay)
                continue
            raise
    raise last


def _poll(probe, predicate, timeout_s=60.0, interval_s=2.0, what=""):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s "
                f"(last observed: {last!r})"
            )
        time.sleep(interval_s)


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """GetParameters lists results alphabetically by name whatever the request order, honours
    version/label selectors, and buckets unresolvable names or selectors into InvalidParameters
    (the singular GetParameter raises); padded names are trimmed for lookup, internal spaces bucket.

    Reference: https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetParameters.html
    """

    ssm = ctx.client("ssm")

    # Names chosen so that alphabetical order is KNOWN and differs from request order.
    # ctx.unique_name supplies the run-unique suffix; the a-/b-/c- prefixes fix the sort.
    stem = ctx.unique_name("sim2real-behav-batchorder-")
    alpha = f"/{stem}-a"
    bravo = f"/{stem}-b"
    charlie = f"/{stem}-c"
    assert [alpha, bravo, charlie] == sorted([alpha, bravo, charlie]), (
        "the three probe names must be constructed in alphabetical order for the "
        f"ordering assertion to mean anything; got {[alpha, bravo, charlie]!r}"
    )

    for name, value in ((alpha, "val-a"), (bravo, "val-b"), (charlie, "val-c")):
        ctx.on_cleanup(lambda n=name: ssm.delete_parameter(Name=n))
        put = _call_with_retry(
            lambda n=name, v=value: ssm.put_parameter(
                Name=n,
                Value=v,
                Type="String",
                Tags=[{"Key": "sim2real", "Value": "get-parameters-batch"}],
            )
        )
        assert put["Version"] == 1, (
            f"the first PutParameter for {name} must mint Version 1, got {put!r}"
        )

    # bravo gets a second version and a label on the FIRST one, so the selectors below
    # resolve to something that is demonstrably not the latest.
    second = _call_with_retry(
        lambda: ssm.put_parameter(
            Name=bravo, Value="val-b-two", Type="String", Overwrite=True
        )
    )
    assert second["Version"] == 2, (
        f"the overwrite of {bravo} must mint Version 2, got {second!r}"
    )
    labelled = _call_with_retry(
        lambda: ssm.label_parameter_version(
            Name=bravo, ParameterVersion=1, Labels=[_LABEL]
        )
    )
    assert labelled.get("InvalidLabels", []) == [], (
        f"a conforming label must not come back under InvalidLabels, got {labelled!r}"
    )

    # --- alphabetical ordering, asked for in reverse -------------------------
    ordered = _poll(
        lambda: ssm.get_parameters(Names=[charlie, bravo, alpha]),
        lambda r: len(r.get("Parameters", [])) == 3,
        what="all three probe parameters being visible to GetParameters",
    )
    got_names = [p["Name"] for p in ordered["Parameters"]]
    assert got_names == [alpha, bravo, charlie], (
        "GetParameters must list results in alphabetical order by name whatever order "
        f"they were requested in; asked for {[charlie, bravo, alpha]!r} and got "
        f"{got_names!r}"
    )
    assert ordered.get("InvalidParameters", []) == [], (
        f"three live names must leave InvalidParameters empty, got "
        f"{ordered.get('InvalidParameters')!r}"
    )
    assert [p["Value"] for p in ordered["Parameters"]] == [
        "val-a",
        "val-b-two",
        "val-c",
    ], (
        "each ordered result must carry its own latest value; got "
        f"{[p['Value'] for p in ordered['Parameters']]!r}"
    )

    # --- selectors resolve, and echo the selector they were asked with -----------
    version_sel = f"{bravo}:1"
    label_sel = f"{bravo}:{_LABEL}"
    selected = ssm.get_parameters(Names=[version_sel, label_sel])
    assert selected.get("InvalidParameters", []) == [], (
        f"both selectors resolve, so InvalidParameters must be empty, got "
        f"{selected.get('InvalidParameters')!r}"
    )
    assert len(selected["Parameters"]) == 2, (
        f"two resolvable selectors must yield two results, got "
        f"{[(p['Name'], p.get('Selector')) for p in selected['Parameters']]!r}"
    )
    by_selector = {p.get("Selector"): p for p in selected["Parameters"]}
    assert sorted(by_selector) == sorted([":1", f":{_LABEL}"]), (
        "each batch result must echo the selector it was asked with; expected "
        f"{sorted([':1', ':' + _LABEL])!r}, got {sorted(by_selector)!r}"
    )
    for selector, param in by_selector.items():
        assert param["Name"] == bravo, (
            f"the returned Name must be the base name, not the selector form; for "
            f"selector {selector!r} it was {param['Name']!r}"
        )
        assert param["Version"] == 1, (
            f"selector {selector!r} pins version 1, which is NOT the latest; got "
            f"version {param['Version']} value {param['Value']!r}"
        )
        assert param["Value"] == "val-b", (
            f"selector {selector!r} must serve the version-1 bytes 'val-b', got "
            f"{param['Value']!r}"
        )

    # --- the same parameter through two selectors is two results ------------
    doubled = ssm.get_parameters(Names=[bravo, version_sel])
    assert len(doubled["Parameters"]) == 2, (
        "the same parameter requested through two different selectors must yield two "
        f"results, not be deduplicated; got "
        f"{[(p['Name'], p.get('Selector'), p['Version']) for p in doubled['Parameters']]!r}"
    )
    doubled_pairs = {
        (p["Version"], p.get("Selector")) for p in doubled["Parameters"]
    }
    assert doubled_pairs == {(2, None), (1, ":1")}, (
        "the unselected entry must be the latest with no Selector and the pinned entry "
        f"must be version 1 with Selector ':1'; got {sorted(map(repr, doubled_pairs))!r}"
    )

    # --- three unresolvable things bucket, alongside three that resolve ---
    ghost = _param_name(ctx, "batch-ghost-")
    bad_version = f"{bravo}:99"
    bad_label = f"{bravo}:sim2real-never-attached"
    mixed = ssm.get_parameters(
        Names=[alpha, ghost, bad_version, bravo, bad_label, charlie]
    )
    resolved = [p["Name"] for p in mixed["Parameters"]]
    assert resolved == [alpha, bravo, charlie], (
        "the resolvable names must come back alphabetically and the unresolvable ones "
        f"must not appear among them; got {resolved!r}"
    )
    assert sorted(mixed.get("InvalidParameters", [])) == sorted(
        [ghost, bad_version, bad_label]
    ), (
        "a nonexistent name, a nonexistent version selector and an unattached label "
        "must ALL be bucketed into InvalidParameters as the exact strings requested "
        f"(GetParameters models no not-found error, so it cannot refuse); expected "
        f"{sorted([ghost, bad_version, bad_label])!r}, got "
        f"{sorted(mixed.get('InvalidParameters', []))!r}"
    )
    # The asymmetry that makes the above discriminating: the SINGULAR form does refuse.
    singular = _error(lambda: ssm.get_parameter(Name=bad_version))
    assert singular.get("Code") == "ParameterVersionNotFound", (
        "the singular GetParameter must refuse the same selector the batch form "
        f"bucketed, which is what makes the batch behaviour a real contract; got "
        f"{singular!r}"
    )
    expected_message = f"Systems Manager could not find version 99 of {bravo.lstrip('/')}. Verify the version and try again."
    assert singular.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {singular.get('Message')!r}"
    )

    # --- leading and trailing spaces are trimmed by the service -------------
    padded_name = f"  {alpha}  "
    padded = ssm.get_parameters(Names=[padded_name])
    assert padded.get("InvalidParameters", []) == [], (
        "a name padded with leading and trailing spaces must be trimmed for lookup and "
        'resolve ("The service removes any spaces specified for the beginning or end of '
        f'a parameter name"); it was bucketed as {padded.get("InvalidParameters")!r}'
    )
    assert len(padded["Parameters"]) == 1, (
        f"the padded name must resolve to exactly one result, got {padded!r}"
    )
    # AWS trims for lookup only: Name is echoed back exactly as requested, padding and all,
    # unlike a selector, whose Name is reported as the base name.
    assert padded["Parameters"][0]["Name"] == padded_name, (
        f"the padded name must be echoed back verbatim, including the padding, got "
        f"{padded['Parameters'][0]['Name']!r}"
    )
    assert padded["Parameters"][0]["Value"] == "val-a", (
        f"the padded name must serve {alpha}'s value, got "
        f"{padded['Parameters'][0]['Value']!r}"
    )

    # --- an INTERNAL space is bucketed, not raised ---------------------------
    # Although the docs prose mentions a ValidationException, GetParameters models no such
    # error and buckets an internally spaced name like any other unresolvable entry.
    inner = f"{alpha[:4]} {alpha[4:]}"
    inner_result = ssm.get_parameters(Names=[inner])
    assert inner_result.get("Parameters", []) == [], (
        "a name with an internal space must not resolve to any parameter, got "
        f"{inner_result.get('Parameters')!r}"
    )
    assert inner_result.get("InvalidParameters", []) == [inner], (
        "a name with an internal space must be bucketed into InvalidParameters as the "
        f"exact requested string, got {inner_result.get('InvalidParameters')!r}"
    )
    # Positive control on the same wiring: the un-spaced name still resolves, so the
    # bucketing above is about the space and not about the batch call.
    control = ssm.get_parameters(Names=[alpha])
    assert [p["Name"] for p in control["Parameters"]] == [alpha], (
        f"the same batch call without the internal space must succeed, got {control!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
