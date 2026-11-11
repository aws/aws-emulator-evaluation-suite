"""create-benefit-application-requires-active-partner-benefit-rejected."""
from __future__ import annotations

import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-benefit-application-requires-active-partner-benefit-rejected"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-benefits"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A well-formed CreateBenefitApplication fails with AccessDeniedException for an account without an active
    partner benefit, while a nonexistent Catalog fails with ResourceNotFoundException, and no application is
    created.
    """
    client = _pcb_client(ctx)

    catalog = "not-a-real-catalog-" + uuid.uuid4().hex[:8]
    control = _error(
        lambda: client.create_benefit_application(
            Catalog=catalog,
            ClientToken=_client_token(),
            BenefitIdentifier="ben-00000000000000",
            Name=ctx.unique_name("sim2real-benapp-"),
        )
    )
    assert control == ("ResourceNotFoundException", f"Catalog `{catalog}` not found"), (
        f"positive control: a nonexistent Catalog must be rejected on its own "
        f"business-logic grounds, got {control!r} -- if this is also "
        f"AccessDeniedException, the account may be denied on every call regardless of "
        f"content, and the entitlement assertion below would not be load-bearing"
    )

    denied = _error(
        lambda: client.create_benefit_application(
            Catalog="Sandbox",
            ClientToken=_client_token(),
            BenefitIdentifier="ben-00000000000000",
            Name=ctx.unique_name("sim2real-benapp-"),
        )
    )
    assert denied == ("AccessDeniedException", _DENIED), (
        f"expected the entitlement AccessDeniedException for a well-formed "
        f"CreateBenefitApplication call, got {denied!r}"
    )

    listed = _error(lambda: client.list_benefit_applications(Catalog="Sandbox", MaxResults=50))
    assert listed == ("AccessDeniedException", _DENIED), (
        f"the read side must be refused by the same entitlement gate as the write side, "
        f"got {listed!r}"
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
