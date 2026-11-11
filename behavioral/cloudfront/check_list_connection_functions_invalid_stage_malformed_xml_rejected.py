"""list-connection-functions-invalid-stage-malformed-xml-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-connection-functions-invalid-stage-malformed-xml-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListConnectionFunctions rejects a Stage outside the DEVELOPMENT|LIVE enum with MalformedXML
    and AWS's exact validation message, while ListDistributions on the same client succeeds."""
    cf = ctx.client("cloudfront")

    code, message = _error_code_and_message(lambda: cf.list_connection_functions(Stage="NOT_A_VALID_STAGE"))
    assert code == "MalformedXML", f"expected MalformedXML, got {code!r}"
    expected = (
        "1 validation error detected: Value 'NOT_A_VALID_STAGE' at 'stage' failed to satisfy "
        "constraint: Member must satisfy enum value set: [LIVE, DEVELOPMENT]"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # Positive control: the rejection is specific to the Stage value, not a broken client.
    control = cf.list_distributions(MaxItems="1")
    assert "DistributionList" in control, f"expected DistributionList in ListDistributions response, got keys {sorted(control)!r}"


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
