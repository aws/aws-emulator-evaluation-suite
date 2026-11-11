"""op-validation-precedence-is-layered."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _expect_error(fn):
    """Call fn, require that it raises, return (ErrorCode, Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")

CHECK = "op-validation-precedence-is-layered"
GROUP = 'overly-permissive'
SERVICES = ['eks']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """[overly-permissive] EKS applies three checks in a fixed order -- identifier syntax, then IAM authorization, then resource resolution -- so a request that is invalid in several ways yields a predictable, specific code rather than a generic 400."""
    c = ctx.client("eks")
    ghost = ctx.unique_name("sim2real-behav-eks-ghost-")

    # (a) Resource resolution beats *semantic* body validation: an add-on name
    #     outside the catalogue is not reported while the parent is missing.
    code, msg = _expect_error(
        lambda: c.create_addon(
            clusterName=ghost, addonName="sim2real-not-a-real-addon"
        )
    )
    assert code == "ResourceNotFoundException", f"addon-on-ghost -> {code}: {msg}"
    assert msg == f"No cluster found for name: {ghost}.", f"addon-on-ghost -> {msg!r}"

    # (b) Identifier *syntax* validation beats resource resolution: a
    #     mis-shaped association id is rejected even though the cluster in the
    #     same request does not exist either.
    code, msg = _expect_error(
        lambda: c.describe_pod_identity_association(
            clusterName=ghost, associationId="!!not-an-id!!"
        )
    )
    assert code == "InvalidParameterException", f"malformed assoc id -> {code}: {msg}"
    assert msg == "The parameter associationId should be 19 characters long.", f"malformed assoc id -> {msg!r}"

    # (c) ...and with a *well-shaped* identifier for a nonexistent association,
    #     resolution governs again.
    code, msg = _expect_error(
        lambda: c.list_pod_identity_associations(clusterName=ghost)
    )
    assert code == "ResourceNotFoundException", f"list-on-ghost -> {code}: {msg}"
    assert msg == f"No cluster found for name: {ghost}.", f"list-on-ghost -> {msg!r}"

    # (d) ...and IAM authorization beats resource resolution too: CreatePodIdentityAssociation
    #     with a cross-account role is denied for iam:PassRole even though the cluster in the
    #     same request is also missing. This is the layer the docstring's "then IAM
    #     authorization" names.
    foreign = f"arn:aws:iam::111122223333:role/{ctx.unique_name('sim2real-behav-eks-foreign-')}"
    code, msg = _expect_error(
        lambda: c.create_pod_identity_association(
            clusterName=ghost, namespace="default", serviceAccount="sim2real-sa", roleArn=foreign
        )
    )
    assert code == "AccessDeniedException", f"pod-identity cross-account role -> {code}: {msg}"
    assert msg == "Cross-account pass role is not allowed.", f"pod-identity cross-account role -> {msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
