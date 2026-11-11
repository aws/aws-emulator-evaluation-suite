"""op-contract-listContinuousDeploymentPolicies."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listContinuousDeploymentPolicies"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListContinuousDeploymentPolicies returns a well-shaped collection; a non-numeric MaxItems yields InvalidArgument."""
    cf = ctx.client("cloudfront")

    resp = cf.list_continuous_deployment_policies()
    body = resp["ContinuousDeploymentPolicyList"]
    assert isinstance(body["Quantity"], int) and body["Quantity"] >= 0, f"expected a non-negative int Quantity, got {body['Quantity']!r}"
    items = body.get("Items", [])
    assert isinstance(items, list), f"expected Items to be a list, got {type(items).__name__}"
    assert len(items) <= body["Quantity"], f"expected len(Items)={len(items)} <= Quantity={body['Quantity']}"
    for item in items:
        assert "Id" in item["ContinuousDeploymentPolicy"], f"expected each summary to carry an Id, got {item}"

    code, msg = _error(lambda: cf.list_continuous_deployment_policies(MaxItems="not-a-number"))
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code}"
    assert msg == "MaxItems must be a non-zero positive integer.", f"unexpected InvalidArgument message: {msg!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    succeeds raises AssertionError: an emulator accepting input real AWS refuses must fail
    loudly, not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
