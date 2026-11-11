"""create-pricing-rule-client-token-reuse-still-payer-gated."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-pricing-rule-client-token-reuse-still-payer-gated"
GROUP = "overly-permissive"
SERVICES = ["billingconductor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """From a non-payer account, CreatePricingRule fails with AccessDeniedException "Account <id> is not
    authorized to call CreatePricingRule. Only payer account is authorized" on the first call, on a repeat
    with the same ClientToken and on a call with a new ClientToken, with the identical message each time."""
    bc = ctx.client("billingconductor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-bc-idem-")
    token_a = ctx.unique_name("sim2real-bc-token-a-")
    token_b = ctx.unique_name("sim2real-bc-token-b-")

    def _attempt(client_token: str):
        return _error_info(
            lambda: bc.create_pricing_rule(
                ClientToken=client_token,
                Name=name,
                Description="markup rule v1",
                Scope="GLOBAL",
                Type="MARKUP",
                ModifierPercentage=10.0,
            )
        )

    code_1, message_1 = _attempt(token_a)
    assert code_1 == "AccessDeniedException", f"first call: unexpected error code: {code_1} ({message_1})"
    expected = f"Account {account_id} is not authorized to call CreatePricingRule. Only payer account is authorized"
    assert message_1 == expected, f"first call: unexpected message: {message_1!r}, expected {expected!r}"

    code_2, message_2 = _attempt(token_a)
    assert code_2 == "AccessDeniedException", (
        f"second call (same ClientToken): unexpected error code: {code_2} ({message_2})"
    )
    assert message_2 == message_1, (
        f"repeating the same ClientToken changed the denial: {message_1!r} -> {message_2!r}"
    )

    code_3, message_3 = _attempt(token_b)
    assert code_3 == "AccessDeniedException", (
        f"third call (different ClientToken): unexpected error code: {code_3} ({message_3})"
    )
    assert message_3 == message_1, (
        f"a fresh ClientToken changed the denial: {message_1!r} -> {message_3!r}"
    )


def _error_info(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return (err["Code"], err.get("Message"))
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
