"""get-blueprint-optimization-status-nonexistent-invocation-not-found-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-blueprint-optimization-status-nonexistent-invocation-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock-data-automation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetBlueprintOptimizationStatus with a pattern-valid invocationArn is refused with
    ValidationException ('The requested operation is not recognized by the service.'), while
    ListBlueprints succeeds for the same caller.
    """
    bda = ctx.client("bedrock-data-automation")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Positive control: an unrelated, always-available BDA read succeeds, so the
    # negative below is attributable to this operation and not to a dead client/account.
    bda.list_blueprints(maxResults=1)

    bogus_invocation_arn = (
        f"arn:aws:bedrock:{ctx.region}:{account_id}:blueprint-optimization-invocation/"
        f"{ctx.unique_name('sim2real-bda-inv').replace('_', '-')}"
    )

    code, msg = _error_code_and_message(
        lambda: bda.get_blueprint_optimization_status(invocationArn=bogus_invocation_arn)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code} ({msg})"
    assert msg == "The requested operation is not recognized by the service.", (
        f"expected the operation-not-recognized message, got: {msg!r}"
    )


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
