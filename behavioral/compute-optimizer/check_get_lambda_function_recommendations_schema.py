"""get-lambda-function-recommendations-schema."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-lambda-function-recommendations-schema"
GROUP = "data-plane"
SERVICES = ["compute-optimizer"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx) -> None:
    """GetLambdaFunctionRecommendations returns only the caller's account's functions with documented
    findings and Lambda ARNs; a well-formed nonexistent ARN filter returns no entries and a malformed one
    fails with InvalidParameterValueException and its exact message."""
    co = ctx.client("compute-optimizer")
    _ensure_opted_in(co)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    resp = co.get_lambda_function_recommendations(maxResults=25)
    recommendations = resp.get("lambdaFunctionRecommendations", [])
    assert isinstance(recommendations, list), f"expected a list, got {type(recommendations)!r}"

    for rec in recommendations:
        assert rec["accountId"] == account_id, (
            f"cross-tenant leak: recommendation accountId {rec['accountId']!r} != caller {account_id!r}"
        )
        assert rec["finding"] in ("Optimized", "NotOptimized", "Unavailable"), (
            f"undocumented finding {rec['finding']!r}"
        )
        expected_prefix = f"arn:aws:lambda:{ctx.region}:{account_id}:function:"
        assert rec["functionArn"].startswith(expected_prefix), (
            f"ARN {rec['functionArn']!r} not scoped to {expected_prefix!r}"
        )

    # Positive control: a syntactically valid ARN for a function that does not exist is accepted
    # (200, no fabricated entry) -- isolates ARN *validity* as the one thing the negative below
    # breaks, rather than "any function we don't own".
    well_formed_missing_arn = (
        f"arn:aws:lambda:{ctx.region}:{account_id}:function:simparity-audit-nonexistent-fn"
    )
    control_resp = co.get_lambda_function_recommendations(
        functionArns=[well_formed_missing_arn], maxResults=25
    )
    assert control_resp.get("lambdaFunctionRecommendations", []) == [], (
        "a well-formed but nonexistent function ARN must not fabricate a recommendation entry"
    )

    code, message = _error(lambda: co.get_lambda_function_recommendations(
        functionArns=["not-a-valid-arn"], maxResults=25
    ))
    assert code == "InvalidParameterValueException", (
        f"malformed function ARN must be rejected as InvalidParameterValueException, got {code!r}"
    )
    expected = "Invalid Lambda function ARN."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _ensure_opted_in(co, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    status = co.get_enrollment_status().get("status")
    if status != "Active":
        co.update_enrollment_status(status="Active")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = co.get_enrollment_status().get("status")
        if status == "Active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"account never reached Active enrollment status, last={status}")


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
