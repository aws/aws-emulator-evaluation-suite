"""guardrail-checks-service-unavailable-distinct-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "guardrail-checks-service-unavailable-distinct-error"
GROUP = "error-semantics"
SERVICES = ["bedrock-runtime"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeGuardrailChecks with an empty checks config is always ValidationException, never a 5xx
    (ServiceUnavailable has no client trigger), while a well-formed content-filter check returns
    structured per-category results."""
    client = ctx.client("bedrock-runtime")
    messages = [{"role": "user", "content": [{"text": "Hello, how has your day been so far?"}]}]

    # Repeated: a flaky or overloaded backend would surface the 5xx classes only intermittently.
    errors = [
        _error_code(lambda: client.invoke_guardrail_checks(messages=messages, checks={}))
        for _ in range(3)
    ]
    expected = ("ValidationException", "At least one check type must be configured")
    assert errors == [expected] * 3, (
        f"an empty checks object must deterministically be ValidationException on every attempt, "
        f"got {errors!r}"
    )

    ok = client.invoke_guardrail_checks(
        messages=messages,
        checks={"contentFilter": {"categories": [{"category": "HATE"}, {"category": "VIOLENCE"}]}},
    )
    filter_result = ok["results"]["contentFilter"]["results"]
    assert len(filter_result) == 2, f"expected 2 contentFilter results, got {filter_result!r}"
    categories_seen = {item["category"] for item in filter_result}
    assert categories_seen == {"HATE", "VIOLENCE"}, (
        f"expected categories {{'HATE', 'VIOLENCE'}}, got {categories_seen!r}"
    )
    for item in filter_result:
        assert 0.0 <= item["severityScore"] <= 1.0, item
    assert ok["usage"]["contentFilter"]["textUnits"] > 0, (
        f"expected positive textUnits usage, got {ok['usage']['contentFilter']!r}"
    )


def _error_code(fn):
    """Return the ClientError (code, message); raise if the call unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call was expected to be refused but returned success")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
