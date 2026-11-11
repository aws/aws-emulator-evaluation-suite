"""op-contract-generateOrganizationsAccessReport."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "op-contract-generateOrganizationsAccessReport"
GROUP = "error-semantics"
SERVICES = ["iam"]

# On a standalone account (not an Organizations management or delegated-admin account)
# both report operations are refused at the entitlement gate with AccessDenied and this generic
# message, before any report job exists.
_GATE_MESSAGE = "You are not authorized to perform this operation."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "identity:standalone", "phase:standalone", "plane:control")
def run(ctx) -> None:
    """GenerateOrganizationsAccessReport on a standalone account is refused with AccessDenied and
    the entitlement-gate message after a positive ListRoles control, and a never-issued JobId is
    refused by GetOrganizationsAccessReport identically."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Positive control: a later rejection can only be attributed to the Organizations gate.
    _, control_code, _ = _try(lambda: iam.list_roles(MaxItems=1))
    assert control_code is None, f"IAM itself unreachable for this caller: {control_code!r}"

    # A syntactically valid, nonexistent org entity path rooted at this account.
    entity_path = f"o-simparityorgid/r-simparityroot/{account_id}"

    resp, code, message = _try(lambda: iam.generate_organizations_access_report(EntityPath=entity_path))
    assert code == "AccessDenied", f"expected AccessDenied for a standalone caller, got {code!r}: {resp or message!r}"
    assert message == _GATE_MESSAGE, f"expected message {_GATE_MESSAGE!r}, got {message!r}"
    # Independent read, same rejection: a JobId that was never issued (because Generate never
    # started a job) cannot be resolved via the destination op.
    fake_job_id = (ctx.unique_name("job-") + "0" * 36)[:36]
    got, get_code, get_message = _try(lambda: iam.get_organizations_access_report(JobId=fake_job_id))
    assert get_code == "AccessDenied", f"expected AccessDenied for a never-issued JobId, got {get_code!r}: {got!r}"
    assert get_message == _GATE_MESSAGE, f"expected message {_GATE_MESSAGE!r}, got {get_message!r}"


def _try(fn) -> tuple[Any, str | None, str | None]:
    from botocore.exceptions import ClientError

    try:
        return fn(), None, None
    except ClientError as exc:
        return None, exc.response["Error"]["Code"], exc.response["Error"].get("Message")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
