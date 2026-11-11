"""update-benefit-application-malformed-identifier-rejected."""
from __future__ import annotations

import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-benefit-application-malformed-identifier-rejected"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-benefits"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateBenefitApplication rejects an Identifier that fails its pattern with the exact
    ValidationException, while a well-formed nonexistent Identifier does not get ValidationException."""
    client = _pcb_client(ctx)

    well_formed_nonexistent = "benappl-" + uuid.uuid4().hex[:14]
    control_code, _ = _error(
        lambda: client.update_benefit_application(
            Catalog="Sandbox",
            ClientToken=_client_token(),
            Identifier=well_formed_nonexistent,
            Revision="1",
            Name=ctx.unique_name("sim2real-benapp-"),
        )
    )
    assert control_code != "ValidationException", (
        f"positive control: a well-formed but nonexistent Identifier "
        f"{well_formed_nonexistent!r} must fail for a reason other than "
        f"ValidationException, got {control_code!r}"
    )

    code, message = _error(
        lambda: client.update_benefit_application(
            Catalog="Sandbox",
            ClientToken=_client_token(),
            Identifier="!!! not a valid identifier !!!",
            Revision="1",
            Name=ctx.unique_name("sim2real-benapp-"),
        )
    )
    expected = _pattern_message("identifier", "(arn:.+|benappl-[0-9a-z]{14})")
    assert code == "ValidationException", f"expected the identifier-pattern ValidationException, got {code!r}: {message!r}"
    assert message == expected, f"expected the identifier-pattern ValidationException message {expected!r}, got {message!r}"


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
