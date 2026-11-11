"""list-namespaces-invalid-input-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-namespaces-invalid-input-error"
GROUP = "error-semantics"
SERVICES = ["servicediscovery"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListNamespaces with a Filter Name outside its enum is refused with InvalidInput and its exact
    message, while an unfiltered call succeeds and a TYPE filter with an unknown value returns an
    empty page."""
    sd = ctx.client("servicediscovery")

    # Positive control: an unfiltered list call succeeds.
    control = sd.list_namespaces()
    assert "Namespaces" in control, f"expected a Namespaces key in the response, got {control!r}"

    # Positive control 2: a well-formed TYPE filter with a value outside the
    # documented Values enum is accepted and simply matches nothing -- this
    # is the "silently returns empty" behavior the malformed-Name case must
    # differ from.
    benign = sd.list_namespaces(
        Filters=[{"Name": "TYPE", "Values": ["NOT_A_REAL_NAMESPACE_TYPE"], "Condition": "EQ"}]
    )
    assert benign["Namespaces"] == [], (
        f"expected an unmatched TYPE value to return an empty page, got {benign['Namespaces']!r}"
    )

    code, message = _error(
        lambda: sd.list_namespaces(
            Filters=[{"Name": "NOT_A_REAL_FILTER_NAME", "Values": ["x"], "Condition": "EQ"}]
        )
    )
    assert code == "InvalidInput", f"expected InvalidInput for a Filter Name outside the enum, got {code!r}"
    assert message == (
        "1 validation error detected: Value 'NOT_A_REAL_FILTER_NAME' at 'filters.1.member.name' "
        "failed to satisfy constraint: Member must satisfy enum value set: [RESOURCE_OWNER, HTTP_NAME, NAME, TYPE]"
    ), f"unexpected InvalidInput message: {message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a Filter Name real AWS rejects is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects a Filter Name outside the NamespaceFilterName enum, but it "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
