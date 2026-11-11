"""payment-instrument-numeric-precision-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "payment-instrument-numeric-precision-preserved"
GROUP = "server-side"
SERVICES = ["bedrock-agentcore"]


@tags("cap:c1", "axis:rejection", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePaymentInstrument and ListPaymentInstruments against a payment manager this caller does not
    own are both denied with AccessDeniedException "Payment manager not found", while an unrelated
    ListABTests succeeds, so the denial is scoped and nothing is partially created."""
    bedrock = ctx.client("bedrock-agentcore")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Positive control: an unrelated, prerequisite-free read proves this principal and the
    # service endpoint are healthy, so the denial below is not "everything is denied".
    bedrock.list_ab_tests()

    payment_manager_arn = (
        f"arn:aws:bedrock-agentcore:{ctx.region}:{account_id}:payment-manager/"
        "s2rprobe-0000000000"
    )
    payment_connector_id = "s2rprobe-connector-0000000000"

    create_code, create_message = _error(
        lambda: bedrock.create_payment_instrument(
            paymentManagerArn=payment_manager_arn,
            paymentConnectorId=payment_connector_id,
            paymentInstrumentType="EMBEDDED_CRYPTO_WALLET",
            paymentInstrumentDetails={
                "embeddedCryptoWallet": {
                    "network": "ETHEREUM",
                    "linkedAccounts": [
                        {"email": {"emailAddress": "sim2real-probe@example.com"}}
                    ],
                }
            },
        )
    )
    assert create_code == "AccessDeniedException", (
        "expected CreatePaymentInstrument against a payment manager this caller does not own "
        f"to be denied AccessDeniedException, got {create_code!r}"
    )

    assert create_message == "Payment manager not found", (
        f"expected the exact denial message on CreatePaymentInstrument, got {create_message!r}"
    )

    list_code, list_message = _error(
        lambda: bedrock.list_payment_instruments(paymentManagerArn=payment_manager_arn)
    )
    assert list_code == "AccessDeniedException", (
        "expected the same AccessDeniedException on an independent read (ListPaymentInstruments) "
        f"against the same unowned manager, got {list_code!r} -- the denied create must not "
        "leave a partially-visible instrument"
    )
    assert list_message == "Payment manager not found", (
        f"expected the exact denial message on ListPaymentInstruments, got {list_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
