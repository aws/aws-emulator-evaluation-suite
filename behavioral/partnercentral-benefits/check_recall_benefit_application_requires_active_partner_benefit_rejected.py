"""recall-benefit-application-requires-active-partner-benefit-rejected."""
from __future__ import annotations

import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "recall-benefit-application-requires-active-partner-benefit-rejected"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-benefits"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A well-formed RecallBenefitApplication from a caller without an active AWS partner benefit gets
    the exact entitlement AccessDeniedException, as does GetBenefitApplication on the same identifier; a
    malformed identifier gets the exact pattern ValidationException."""
    client = _pcb_client(ctx)

    control = _error(
        lambda: client.recall_benefit_application(
            Catalog="Sandbox",
            ClientToken=_client_token(),
            Identifier="!!! not a valid identifier !!!",
            Reason="sim2real positive-control probe",
        )
    )
    expected = _pattern_message("identifier", "(arn:.+|benappl-[0-9a-z]{14})")
    assert control == ("ValidationException", expected), (
        f"positive control: expected the identifier-pattern ValidationException "
        f"(proving the account/credentials reach the service), got {control!r}"
    )

    identifier = "benappl-00000000000000"
    recall = _error(
        lambda: client.recall_benefit_application(
            Catalog="Sandbox",
            ClientToken=_client_token(),
            Identifier=identifier,
            Reason="sim2real entitlement-gate probe",
        )
    )
    assert recall == ("AccessDeniedException", _DENIED), (
        f"expected the entitlement AccessDeniedException for a well-formed "
        f"RecallBenefitApplication call, got {recall!r}"
    )

    read = _error(
        lambda: client.get_benefit_application(Catalog="Sandbox", Identifier=identifier)
    )
    assert read == ("AccessDeniedException", _DENIED), (
        f"expected the independent GetBenefitApplication read to hit the same "
        f"entitlement gate rather than succeed or 404, got {read!r}"
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
