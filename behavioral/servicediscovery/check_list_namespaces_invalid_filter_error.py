"""list-namespaces-invalid-filter-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-namespaces-invalid-filter-error"
GROUP = "error-semantics"
SERVICES = ["servicediscovery"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListNamespaces with a NAME filter using BETWEEN is refused with InvalidInput and the exact
    message listing NAME's supported conditions, while a NAME EQ filter succeeds with no matches."""
    sd = ctx.client("servicediscovery")

    code, message = _error(
        lambda: sd.list_namespaces(
            Filters=[{"Name": "NAME", "Values": ["a", "b"], "Condition": "BETWEEN"}]
        )
    )
    assert code == "InvalidInput", f"expected InvalidInput for NAME+BETWEEN filter, got {code!r}"
    assert message == "Invalid filter condition(s) provided: filter NAME supports condition(s) [BEGINS_WITH, EQ], but got BETWEEN; ", f"unexpected InvalidInput message: {message!r}"

    # Positive control: a well-formed filter (EQ, single value) still succeeds, even with no
    # matches for a name that was never created.
    resp = sd.list_namespaces(
        Filters=[{"Name": "NAME", "Values": [ctx.unique_name("sim2real-no-such-ns")], "Condition": "EQ"}]
    )
    assert resp["Namespaces"] == [], f"expected no namespaces for a name never created, got {resp['Namespaces']!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects NAME+BETWEEN filter, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
