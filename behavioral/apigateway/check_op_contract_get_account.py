"""op-contract-get-account."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-get-account"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:apigateway-account")
def run(ctx) -> None:
    """GetAccount returns the throttle settings and a stable apiKeyVersion; via UpdateAccount, a
    valid patch clearing cloudwatchRoleArn succeeds (positive control) and an invalid JSON Patch
    path is rejected with BadRequestException, leaving GetAccount's cloudwatchRoleArn unchanged."""
    apigw = ctx.client("apigateway")

    before = apigw.get_account()
    assert isinstance(before.get("apiKeyVersion"), str) and before["apiKeyVersion"], (
        f"expected a non-empty apiKeyVersion string, got {before.get('apiKeyVersion')!r}"
    )
    throttle = before["throttleSettings"]
    assert isinstance(throttle["rateLimit"], (int, float)) and throttle["rateLimit"] > 0, (
        f"expected a positive rateLimit, got {throttle.get('rateLimit')!r}"
    )
    assert isinstance(throttle["burstLimit"], int) and throttle["burstLimit"] > 0, (
        f"expected a positive burstLimit, got {throttle.get('burstLimit')!r}"
    )
    before_role = before.get("cloudwatchRoleArn", "")

    # a second read is consistent (read-only, deterministic contract)
    again = apigw.get_account()
    assert again["apiKeyVersion"] == before["apiKeyVersion"], (
        f"apiKeyVersion changed across reads: {before['apiKeyVersion']!r} -> {again['apiKeyVersion']!r}"
    )
    assert again.get("cloudwatchRoleArn", "") == before_role, (
        f"cloudwatchRoleArn changed across reads: {before_role!r} -> {again.get('cloudwatchRoleArn')!r}"
    )

    def _restore():
        apigw.update_account(
            patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": before_role}]
        )

    ctx.on_cleanup(_restore)

    # positive control: a valid patch succeeds, proving UpdateAccount works on this account
    # at all -- clearing cloudwatchRoleArn is the one value real AWS accepts unconditionally.
    positive = apigw.update_account(
        patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": ""}]
    )
    assert positive.get("cloudwatchRoleArn", "") == "", (
        f"expected the positive-control patch to clear cloudwatchRoleArn, got {positive.get('cloudwatchRoleArn')!r}"
    )
    confirmed = apigw.get_account()
    assert confirmed.get("cloudwatchRoleArn", "") == "", (
        f"positive-control patch not reflected on GetAccount, got {confirmed.get('cloudwatchRoleArn')!r}"
    )

    # error boundary: an invalid JSON Patch path on the account resource -> BadRequestException,
    # and the account's cloudwatchRoleArn is left unchanged as observed via GetAccount.
    code, message = _error(
        lambda: apigw.update_account(
            patchOperations=[{"op": "replace", "path": "/notARealField", "value": "x"}]
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == (
        "Invalid patch path  '/notARealField' specified for op 'replace'. "
        "Must be one of: [/cloudwatchRoleArn]"
    ), f"unexpected BadRequestException message {message!r}"
    after = apigw.get_account()
    assert after.get("cloudwatchRoleArn", "") == "", (
        f"cloudwatchRoleArn changed after a rejected update: expected '', got {after.get('cloudwatchRoleArn')!r}"
    )
    assert after["apiKeyVersion"] == before["apiKeyVersion"], (
        f"apiKeyVersion changed after a rejected update: {before['apiKeyVersion']!r} -> {after['apiKeyVersion']!r}"
    )


# ===== helpers (self-contained) =====
def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
