"""op-pod-identity-identifier-validation."""
from __future__ import annotations

import uuid

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

CHECK = "op-pod-identity-identifier-validation"
GROUP = 'overly-permissive'
SERVICES = ['eks']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On a missing cluster, Describe/DeletePodIdentityAssociation answer a malformed associationId with
    InvalidParameterException (19 characters required) and a well-shaped one with ResourceNotFoundException
    naming the cluster, each with its exact message: the shape is checked first."""
    c = ctx.client("eks")
    ghost = ctx.unique_name("sim2real-behav-eks-ghost-")
    malformed = "!!not-an-id!!"
    well_shaped = "a-" + uuid.uuid4().hex[:17]  # right length (19), no real association behind it

    code, msg = _expect_error(
        lambda: c.describe_pod_identity_association(clusterName=ghost, associationId=malformed)
    )
    assert code == "InvalidParameterException", f"describe malformed -> {code}: {msg}"
    assert msg == "The parameter associationId should be 19 characters long.", f"describe malformed -> {msg!r}"

    code, msg = _expect_error(
        lambda: c.delete_pod_identity_association(clusterName=ghost, associationId=malformed)
    )
    assert code == "InvalidParameterException", f"delete malformed -> {code}: {msg}"
    assert msg == "The parameter associationId should be 19 characters long.", f"delete malformed -> {msg!r}"

    code, msg = _expect_error(
        lambda: c.describe_pod_identity_association(clusterName=ghost, associationId=well_shaped)
    )
    assert code == "ResourceNotFoundException", f"describe well-shaped -> {code}: {msg}"
    assert msg == f"No cluster found for name: {ghost}.", f"describe well-shaped -> {msg!r}"

    code, msg = _expect_error(
        lambda: c.delete_pod_identity_association(clusterName=ghost, associationId=well_shaped)
    )
    assert code == "ResourceNotFoundException", f"delete well-shaped -> {code}: {msg}"
    assert msg == f"No cluster found for name: {ghost}.", f"delete well-shaped -> {msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
