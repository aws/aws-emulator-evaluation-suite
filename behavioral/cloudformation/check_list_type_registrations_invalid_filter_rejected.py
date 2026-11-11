"""list-type-registrations-invalid-filter-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-type-registrations-invalid-filter-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTypeRegistrations rejects a syntactically invalid RegistrationStatusFilter value
    (not one of COMPLETE | IN_PROGRESS | FAILED) with a ValidationError -- while the
    same call using a valid filter value succeeds."""
    from botocore.exceptions import ClientError

    cfn = ctx.client("cloudformation")
    type_name = _extension_type_name(ctx, "Amb")

    try:
        cfn.list_type_registrations(
            TypeName=type_name, Type="RESOURCE", RegistrationStatusFilter="NOT_A_REAL_STATUS"
        )
        raise AssertionError(
            "expected a ValidationError for an invalid RegistrationStatusFilter value"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ValidationError", f"unexpected error code: {code}"
        message = exc.response["Error"].get("Message")
        assert message == (
            "1 validation error detected: Value 'NOT_A_REAL_STATUS' at 'registrationStatusFilter' "
            "failed to satisfy constraint: Member must satisfy enum value set: [IN_PROGRESS, COMPLETE, FAILED]"
        ), f"unexpected ValidationError message {message!r}"

    # Positive control: the same TypeName/Type with a valid filter value is well-formed and
    # must succeed (an empty result list is fine -- the type was never registered).
    control = cfn.list_type_registrations(
        TypeName=type_name, Type="RESOURCE", RegistrationStatusFilter="COMPLETE"
    )
    assert control["RegistrationTokenList"] == [], (
        f"expected an empty RegistrationTokenList for a never-registered type, "
        f"got: {control['RegistrationTokenList']}"
    )


def _extension_type_name(ctx, tag):
    token = "".join(ch for ch in ctx.unique_name(tag) if ch.isalnum())
    if len(token) < 2:
        token = (token + "abcdefgh")[:8]
    token = token[:40]
    return f"S2R{tag[:6].capitalize()}::{token}::Behav"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
