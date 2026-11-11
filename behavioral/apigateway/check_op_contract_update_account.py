"""op-contract-updateAccount."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-updateAccount"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:apigateway-account")
def run(ctx) -> None:
    """UpdateAccount patches the account-level cloudwatchRoleArn; an unrecognized patch path -> BadRequestException."""
    apigw = ctx.client("apigateway")

    original = apigw.get_account().get("cloudwatchRoleArn", "")

    def _restore():
        if original:
            apigw.update_account(patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": original}])
        else:
            apigw.update_account(patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": ""}])

    ctx.on_cleanup(_restore)

    updated = apigw.update_account(
        patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": ""}]
    )
    assert updated.get("cloudwatchRoleArn", "") == "", (
        f"expected UpdateAccount's own response to reflect the cleared cloudwatchRoleArn, "
        f"got {updated.get('cloudwatchRoleArn')!r}"
    )

    refetched = apigw.get_account()
    assert refetched.get("cloudwatchRoleArn", "") == "", (
        f"expected the clear to persist on an independent GetAccount, "
        f"got {refetched.get('cloudwatchRoleArn')!r}"
    )

    code, message = _error(
        lambda: apigw.update_account(
            patchOperations=[{"op": "replace", "path": "/notARealAccountField", "value": "x"}]
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == (
        "Invalid patch path  '/notARealAccountField' specified for op 'replace'. Must be one of: [/cloudwatchRoleArn]"
    ), f"unexpected {code} message: {message!r}"

    # the forbidden effect did not happen: cloudwatchRoleArn is unchanged by the rejected patch
    after = apigw.get_account()
    assert after.get("cloudwatchRoleArn", "") == "", (
        f"expected cloudwatchRoleArn to remain unchanged after a rejected patch, "
        f"got {after.get('cloudwatchRoleArn')!r}"
    )


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise. An
    unexpected success raises, so an over-permissive target cannot pass as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
