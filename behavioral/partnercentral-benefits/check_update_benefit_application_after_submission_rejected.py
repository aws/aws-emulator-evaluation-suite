"""update-benefit-application-after-submission-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-benefit-application-after-submission-rejected"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-benefits"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """For a caller without an active AWS partner benefit, CreateBenefitApplication,
    UpdateBenefitApplication on a nonexistent identifier and ListBenefitApplications all get the exact
    entitlement AccessDeniedException; a malformed resourceArn gets the exact ValidationException."""
    client = _pcb_client(ctx)
    catalog = "Sandbox"

    # Positive control: the account and credentials reach the service and get a
    # correctly-parsed rejection, ruling out a transport/credential failure being
    # mistaken for the entitlement gate below.
    control_code, control_message = _error_code(
        lambda: client.list_tags_for_resource(resourceArn="not-an-arn")
    )
    assert control_code == "ValidationException", (
        f"positive control failed: expected ValidationException for a malformed "
        f"resourceArn, got {control_code!r} -- cannot attribute the gate below to "
        f"entitlement rather than a broken connection"
    )
    expected_control = (
        "1 validation error detected: Value at 'resourceArn' failed to satisfy constraint: "
        r"Member must satisfy regular expression pattern: arn:[\w+=/,.@-]+:partnercentral:"
        r"[\w+=/,.@-]*:[0-9]{12}:catalog/([a-zA-Z]+)/[\w+=,.@-]+(/[\w+=,.@-]+)*"
    )
    assert control_message == expected_control, (
        f"expected the positive control message {expected_control!r}, got {control_message!r}"
    )

    # The specific refusal: CreateBenefitApplication needs an active AWS partner
    # benefit, which the caller does not hold.
    create_code = None
    create_message = ""
    try:
        client.create_benefit_application(
            Catalog=catalog,
            ClientToken=_client_token(),
            BenefitIdentifier="ben-00000000000000",
            Name=ctx.unique_name("sim2real-benapp-"),
        )
    except ClientError as exc:
        create_code = exc.response["Error"]["Code"]
        create_message = exc.response["Error"].get("Message", "")
    assert create_code == "AccessDeniedException", (
        f"expected AccessDeniedException for CreateBenefitApplication from an account "
        f"with no active partner benefit, got {create_code!r}"
    )
    assert create_message == _DENIED, (
        f"expected the AccessDeniedException message {_DENIED!r} naming the missing partner "
        f"benefit entitlement, got {create_message!r}"
    )

    # The named operation hits the same entitlement gate: there is no application to update.
    update = _error_code(
        lambda: client.update_benefit_application(
            Catalog=catalog,
            ClientToken=_client_token(),
            Identifier="benappl-00000000000000",
            Revision="1",
            Name=ctx.unique_name("sim2real-benapp-"),
        )
    )
    assert update == ("AccessDeniedException", _DENIED), (
        f"expected UpdateBenefitApplication to be denied by the entitlement gate, got {update!r}"
    )

    # Effect-absent, independent read: there is no application to have created (the
    # call above never succeeded), and the read path itself is denied the same way --
    # the caller has no side door onto BenefitApplication at all.
    list_code = None
    list_message = ""
    try:
        client.list_benefit_applications(Catalog=catalog)
    except ClientError as exc:
        list_code = exc.response["Error"]["Code"]
        list_message = exc.response["Error"].get("Message", "")
    assert list_code == "AccessDeniedException", (
        f"expected ListBenefitApplications to be denied by the same entitlement gate "
        f"as CreateBenefitApplication, got {list_code!r}"
    )
    assert list_message == _DENIED, (
        f"expected the ListBenefitApplications AccessDeniedException message {_DENIED!r}, "
        f"got {list_message!r}"
    )


_DENIED = (
    "This action requires an active AWS partner benefit. Register as an AWS partner if "
    "you haven't already, or contact AWS partner central support."
)


def _pcb_client(ctx):
    """partnercentral-benefits serves only us-east-1, at an api.aws host botocore does not
    resolve by default; ctx.service_url names that host on real AWS and the target's endpoint
    otherwise."""
    from botocore.config import Config

    return ctx.client(
        "partnercentral-benefits",
        region="us-east-1",
        config=Config(retries={"max_attempts": 8, "mode": "standard"}),
        endpoint_url=ctx.service_url("https://partnercentral-benefits.us-east-1.api.aws"),
    )


def _client_token() -> str:
    import uuid

    return "ct-" + uuid.uuid4().hex


def _error_code(fn):
    """(Code, Message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
