"""op-contract-detachGroupPolicy."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-detachGroupPolicy"
GROUP = "error-semantics"
SERVICES = ["iam"]

_DENY_ALL_POLICY_ARN = "arn:aws:iam::aws:policy/AWSDenyAll"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DetachGroupPolicy removes the attachment; NoSuchEntity when the policy isn't attached."""
    iam = ctx.client("iam")

    group_name = ctx.unique_name("sim2real-behav-grp-detach-")
    iam.create_group(GroupName=group_name)
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group_name))

    iam.attach_group_policy(GroupName=group_name, PolicyArn=_DENY_ALL_POLICY_ARN)
    attached = [p["PolicyArn"] for p in iam.list_attached_group_policies(GroupName=group_name)["AttachedPolicies"]]
    assert _DENY_ALL_POLICY_ARN in attached, f"expected {_DENY_ALL_POLICY_ARN} attached, got {attached}"

    # success path
    resp = iam.detach_group_policy(GroupName=group_name, PolicyArn=_DENY_ALL_POLICY_ARN)
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected HTTP 200 from DetachGroupPolicy, got {status}"
    attached_after = [
        p["PolicyArn"] for p in iam.list_attached_group_policies(GroupName=group_name)["AttachedPolicies"]
    ]
    assert _DENY_ALL_POLICY_ARN not in attached_after, (
        f"expected {_DENY_ALL_POLICY_ARN} detached, still present in {attached_after}"
    )

    # error boundary: detaching a policy that is not currently attached -> NoSuchEntityException
    code, code_msg = _client_error(lambda: iam.detach_group_policy(GroupName=group_name, PolicyArn=_DENY_ALL_POLICY_ARN))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    assert code_msg == f"Policy {_DENY_ALL_POLICY_ARN} was not found.", f"unexpected error message {code_msg!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
