"""update-provisioned-limit-over-quota-rejected."""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-provisioned-limit-over-quota-rejected"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]

_LIMIT_DEFINITION = {"LimitClass": "API_CATEGORY", "Attributes": {"Category": "UserCreation"}}
# Far above any account's provisioned-limit ceiling for this category.
_ABSURD_VALUE = 2_000_000_000


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:cognito-idp-provisioned-limits")
def run(ctx) -> None:
    """UpdateProvisionedLimit above the account's ceiling fails with ServiceQuotaExceededException and a
    message naming a ceiling at least the current value, while concurrent and later GetProvisionedLimit
    reads all return the unchanged baseline."""
    cognito = ctx.client("cognito-idp")

    original = cognito.get_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION)["Limit"]
    original_value = original["ProvisionedLimitValue"]
    assert original_value > 0, f"unexpected baseline ProvisionedLimitValue: {original}"

    def _restore():
        try:
            cognito.update_provisioned_limit(
                LimitDefinition=_LIMIT_DEFINITION, RequestedLimitValue=original_value
            )
        except ClientError as exc:
            # A target with no purchased headroom rejects even this no-op restore -- the value
            # never moved in the first place, so there is nothing to undo.
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise

    ctx.on_cleanup(_restore)

    errors: dict[str, str] = {}
    reads: list[int] = []

    def bogus():
        try:
            cognito.update_provisioned_limit(
                LimitDefinition=_LIMIT_DEFINITION, RequestedLimitValue=_ABSURD_VALUE
            )
        except ClientError as exc:
            errors["code"] = exc.response["Error"]["Code"]
            errors["message"] = exc.response["Error"]["Message"]

    def concurrent_reads():
        for _ in range(5):
            reads.append(
                cognito.get_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION)["Limit"][
                    "ProvisionedLimitValue"
                ]
            )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_bogus = pool.submit(bogus)
        fut_reads = pool.submit(concurrent_reads)
        fut_bogus.result()
        fut_reads.result()

    # (a) exact rejection code and message shape -- the ceiling is captured, not assumed, so an
    # account with purchased headroom (a higher ceiling than its current value) still matches.
    assert errors.get("code") == "ServiceQuotaExceededException", errors
    match = re.fullmatch(
        rf"Requested value {_ABSURD_VALUE} exceeds Service Quota ceiling of (\d+)",
        errors.get("message", ""),
    )
    assert match, f"unexpected rejection message: {errors.get('message')!r}"
    ceiling = int(match.group(1))
    assert ceiling >= original_value, (
        f"reported ceiling {ceiling} is below the account's own current value {original_value}"
    )

    # (b) no read concurrent with the rejected write ever observed the absurd value, or anything
    # other than the baseline -- the in-flight rejection never became visible.
    assert reads, "the concurrent reader never completed a read"
    assert all(v == original_value for v in reads), (
        f"a read concurrent with the rejected write observed {reads}, expected every read to "
        f"stay at the baseline {original_value}"
    )

    # (c) effect absent, and the positive control still works after the rejection: an independent
    # read once the race has settled shows the baseline unmoved and the API unwedged.
    final = cognito.get_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION)["Limit"]
    assert final["ProvisionedLimitValue"] != _ABSURD_VALUE, (
        f"the absurd value {_ABSURD_VALUE} took hold despite being rejected"
    )
    assert final["ProvisionedLimitValue"] == original_value, (
        f"ProvisionedLimitValue drifted from {original_value} to "
        f"{final['ProvisionedLimitValue']} across a rejected write"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
