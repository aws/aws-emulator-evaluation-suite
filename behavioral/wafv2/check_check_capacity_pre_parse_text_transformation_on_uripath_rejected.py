"""check-capacity-pre-parse-text-transformation-on-uripath-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "check-capacity-pre-parse-text-transformation-on-uripath-rejected"
GROUP = 'capacity'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

_UNSUPPORTED_FIELD = (
    "WAFInvalidParameterException",
    "Error reason: PreParseTextTransformations is only supported for SingleQueryArgument "
    "and AllQueryArguments field to match types., field: PRE_PARSE_TEXT_TRANSFORMATION, "
    "parameter: PreParseTextTransformation",
)


def _visibility_config(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}


def _byte_match_statement(field_to_match):
    return {
        "ByteMatchStatement": {
            "SearchString": b"probe",
            "FieldToMatch": field_to_match,
            "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            "PreParseTextTransformations": [{"Priority": 0, "Type": "URL_DECODE"}],
            "PositionalConstraint": "CONTAINS",
        }
    }


def _rule(statement, name="probe", priority=0):
    return {
        "Name": name,
        "Priority": priority,
        "Statement": statement,
        "Action": {"Count": {}},
        "VisibilityConfig": _visibility_config(name.replace("-", "")),
    }


def expect_error(fn, code, message):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == code, f"expected {code}, got {err.get('Code')}: {err.get('Message')!r}"
        assert err.get("Message") == message, f"unexpected message {err.get('Message')!r}"
        return
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CheckCapacity refuses PreParseTextTransformations on a ByteMatchStatement whose
    FieldToMatch is UriPath, and still reports capacity for the same statement on
    SingleQueryArgument, which the field supports.
    """
    w = ctx.client("wafv2")

    expect_error(
        lambda: w.check_capacity(
            Scope=SCOPE, Rules=[_rule(_byte_match_statement({"UriPath": {}}))]
        ),
        *_UNSUPPORTED_FIELD,
    )

    control = w.check_capacity(
        Scope=SCOPE,
        Rules=[_rule(_byte_match_statement({"SingleQueryArgument": {"Name": "q"}}))],
    )
    assert control["Capacity"] == 30, f"expected 30 WCU, got {control['Capacity']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
