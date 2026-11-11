"""update-provisioned-limit-concurrent-writes-conflict."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-provisioned-limit-concurrent-writes-conflict"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:cognito-idp-provisioned-limits")
def run(ctx) -> None:
    """Two concurrent UpdateProvisionedLimit calls far above any account's ceiling both fail with
    ServiceQuotaExceededException and leave the limit unchanged, and an update to the free limit then
    lands (or is refused as unchanged when already there), as GetProvisionedLimit confirms."""
    cognito = ctx.client("cognito-idp")
    limit_definition = {
        "LimitClass": "API_CATEGORY",
        "Attributes": {"Category": "UserResourceRead"},
    }

    original = cognito.get_provisioned_limit(LimitDefinition=limit_definition)["Limit"]
    original_value = original["ProvisionedLimitValue"]
    free_value = original["FreeLimitValue"]

    def _restore():
        try:
            cognito.update_provisioned_limit(
                LimitDefinition=limit_definition, RequestedLimitValue=original_value
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException" and not _is_same_value(exc):
                raise

    ctx.on_cleanup(_restore)
    # A category never written accepts the value it reports once; provision it explicitly.
    _restore()

    # Values this far above the free-tier default exceed any realistic account-level max
    # limit (which defaults to the free rate until a Service Quotas increase is approved),
    # so both concurrent racers must lose -- with no billing impact since neither commits.
    huge_a = 1_000_000_000
    huge_b = 1_000_000_001

    def _call(value):
        return cognito.update_provisioned_limit(
            LimitDefinition=limit_definition, RequestedLimitValue=value
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_call, huge_a)
        fut_b = pool.submit(_call, huge_b)
        codes = []
        messages = []
        for fut in (fut_a, fut_b):
            try:
                fut.result()
                codes.append(None)
                messages.append(None)
            except ClientError as exc:
                codes.append(exc.response["Error"]["Code"])
                messages.append(exc.response["Error"].get("Message") or "")

    assert codes == ["ServiceQuotaExceededException", "ServiceQuotaExceededException"], (
        f"expected both concurrent out-of-range requests to be rejected identically, got {codes}"
    )
    # The ceiling is the account's Service Quotas value, which no read here returns.
    for value, message in zip((huge_a, huge_b), messages):
        assert message.startswith(f"Requested value {value} exceeds Service Quota ceiling of "), message

    # Effect absent: contention over an illegal value left the real limit untouched.
    unchanged = cognito.get_provisioned_limit(LimitDefinition=limit_definition)["Limit"]
    assert unchanged["ProvisionedLimitValue"] == original_value, (
        "provisioned limit changed even though both concurrent requests were rejected"
    )

    # Positive control: a legitimate, no-cost update (back to the free/default rate) still
    # works, proving the operation itself functions and the rejections above were value-specific.
    # A limit already at the free rate refuses it as unchanged instead.
    if original_value != free_value:
        restored = cognito.update_provisioned_limit(
            LimitDefinition=limit_definition, RequestedLimitValue=free_value
        )["Limit"]
        assert restored["ProvisionedLimitValue"] == free_value, (
            f"expected the positive-control update to echo {free_value}, got {restored['ProvisionedLimitValue']}"
        )
    else:
        try:
            cognito.update_provisioned_limit(LimitDefinition=limit_definition, RequestedLimitValue=free_value)
        except ClientError as exc:
            assert _is_same_value(exc), exc.response["Error"]
        else:
            raise AssertionError(f"re-requesting the provisioned {free_value} was accepted, not refused as unchanged")

    # Terminal read: an independent GetProvisionedLimit (not the mutating call's own
    # response) confirms the positive control actually landed server-side.
    confirmed = cognito.get_provisioned_limit(LimitDefinition=limit_definition)["Limit"]
    assert confirmed["ProvisionedLimitValue"] == free_value, (
        f"expected GetProvisionedLimit to read back {free_value} after the positive-control "
        f"update, got {confirmed['ProvisionedLimitValue']}"
    )


def _is_same_value(exc: ClientError) -> bool:
    """UpdateProvisionedLimit's refusal of the value already provisioned."""
    return (exc.response["Error"]["Code"], exc.response["Error"].get("Message")) == (
        "InvalidParameterException", "Requested value is the same as the current provisioned limit"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
