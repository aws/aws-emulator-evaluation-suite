"""op-contract-getDelegationRequest."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getDelegationRequest"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDelegationRequest rejects a nonexistent id with NoSuchEntity; CreateDelegationRequest from
    a non-partner account rejects the PolicyTemplateArn with ValidationError and lists nothing.
    Both errors carry AWS's exact message."""
    iam = ctx.client("iam")
    op_names = iam.meta.service_model.operation_names
    if "GetDelegationRequest" not in op_names:
        raise AssertionError("unreachable: GetDelegationRequest not supported by installed botocore version")

    # IAM's wire-level Code for this shape is "NoSuchEntity" (the modeled exception
    # class name "NoSuchEntityException" is not the on-the-wire Code).
    fake_id = "sim2real0000000000nonexistent0000"
    err = _error(lambda: iam.get_delegation_request(DelegationRequestId=fake_id))
    assert err["Code"] == "NoSuchEntity", f"expected NoSuchEntity, got {err!r}"
    expected = f"DelegationRequest not found: {fake_id}"
    assert err.get("Message") == expected, f"expected message {expected!r}, got {err!r}"

    if "CreateDelegationRequest" not in op_names:
        return

    # CreateDelegationRequest is "not available for general use" without partner onboarding, so
    # any PolicyTemplateArn is refused with an unmodeled ValidationError whichever account owns it.
    description = ctx.unique_name("sim2real-delegation-")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    unreachable_template_arn = f"arn:aws:iam::{account_id}:policy-template/{ctx.unique_name('sim2real-tmpl-')}"
    err = _error(lambda: iam.create_delegation_request(
        Description=description,
        Permissions={"PolicyTemplateArn": unreachable_template_arn},
        RequestorWorkflowId=ctx.unique_name("sim2real-workflow-"),
        NotificationChannel="none",
        SessionDuration=3600,
    ))
    assert err["Code"] == "ValidationError", f"expected ValidationError, got {err!r}"
    expected = "Invalid ARN:  Could not be parsed!"
    assert err.get("Message") == expected, f"expected message {expected!r}, got {err!r}"

    listed = iam.list_delegation_requests().get("DelegationRequests", [])
    assert not any(d.get("Description") == description for d in listed), (
        f"rejected CreateDelegationRequest nonetheless left a listed request behind: {description!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return dict(e.response["Error"])
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
