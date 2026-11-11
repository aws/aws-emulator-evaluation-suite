"""amend-benefit-application-malformed-identifier-rejected."""
from __future__ import annotations

import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "amend-benefit-application-malformed-identifier-rejected"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-benefits"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AmendBenefitApplication with an Identifier that matches neither the application-id nor the ARN pattern
    fails with ValidationException, while a well-formed nonexistent Identifier fails with a different code at
    the later lookup or authorization stage.
    """
    client = _pcb_client(ctx)

    control = _error(
        lambda: client.amend_benefit_application(
            Catalog="Sandbox",
            ClientToken=_client_token(),
            Revision="1",
            Identifier="benappl-00000000000001",
            AmendmentReason="sim2real entitlement/existence control",
            Amendments=[{"FieldPath": "$.Description", "NewValue": "x"}],
        )
    )
    assert control == ("AccessDeniedException", _DENIED), (
        f"expected the well-formed-but-nonexistent control identifier to be refused "
        f"downstream by the entitlement gate, got {control!r}"
    )

    refusal = _error(
        lambda: client.amend_benefit_application(
            Catalog="Sandbox",
            ClientToken=_client_token(),
            Revision="1",
            Identifier="!!! not a valid identifier !!!",
            AmendmentReason="sim2real malformed identifier probe",
            Amendments=[{"FieldPath": "$.Description", "NewValue": "x"}],
        )
    )
    expected = _pattern_message("identifier", "(arn:.+|benappl-[0-9a-z]{14})")
    assert refusal == ("ValidationException", expected), (
        f"expected the identifier-pattern ValidationException, got {refusal!r}"
    )


_DENIED = (
    "This action requires an active AWS partner benefit. Register as an AWS partner if "
    "you haven't already, or contact AWS partner central support."
)


def _pattern_message(member: str, pattern: str) -> str:
    """The exact ValidationException message for a member that fails its modelled pattern."""
    return (
        f"1 validation error detected: Value at '{member}' failed to satisfy constraint: "
        f"Member must satisfy regular expression pattern: {pattern}"
    )


def _pcb_client(ctx):
    """partnercentral-benefits serves only us-east-1, at an api.aws host botocore does not
    resolve by default; ctx.service_url names that host on real AWS and the target's endpoint
    otherwise."""
    return ctx.client(
        "partnercentral-benefits",
        region="us-east-1",
        endpoint_url=ctx.service_url("https://partnercentral-benefits.us-east-1.api.aws"),
        config=Config(retries={"max_attempts": 8, "mode": "standard"}),
    )


def _client_token() -> str:
    return "ct-" + uuid.uuid4().hex


def _error(fn):
    """(Code, Message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
