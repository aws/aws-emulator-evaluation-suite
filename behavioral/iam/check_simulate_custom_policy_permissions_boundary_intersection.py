"""simulate-custom-policy-permissions-boundary-intersection."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "simulate-custom-policy-permissions-boundary-intersection"
GROUP = 'policy_simulation'
SERVICES = ['iam']

IDENTITY_ALLOW_ALL_S3 = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "IdentityAllowAllS3", "Effect": "Allow", "Action": "s3:*", "Resource": "*"}
        ],
    }
)
BOUNDARY_READ_ONLY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "BoundaryReadOnly",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": "*",
            }
        ],
    }
)


def _by_action(results):
    return {r["EvalActionName"]: r for r in results}


@tags("axis:happy-path", "cap:c7", "plane:control")
def run(ctx) -> None:
    """A permissions boundary in SimulateCustomPolicy intersects the identity policy: an action
    both allow is 'allowed' (AllowedByPermissionsBoundary true); one only the identity policy
    allows is 'implicitDeny' with the boundary as the blocker."""
    iam = ctx.client("iam")
    actions = ["s3:GetObject", "s3:DeleteObject"]

    # --- Control first: with no boundary, the identity policy allows BOTH actions. Establishes
    # that any implicitDeny below is attributable to the boundary and nothing else.
    unbounded = _by_action(
        iam.simulate_custom_policy(
            PolicyInputList=[IDENTITY_ALLOW_ALL_S3], ActionNames=actions
        )["EvaluationResults"]
    )
    for action in actions:
        assert unbounded[action]["EvalDecision"] == "allowed", (
            f"without a boundary, s3:* must allow {action}; got "
            f"{unbounded[action]['EvalDecision']!r}"
        )

    # --- Same identity policy, now intersected with a read-only boundary.
    bounded_results = iam.simulate_custom_policy(
        PolicyInputList=[IDENTITY_ALLOW_ALL_S3],
        PermissionsBoundaryPolicyInputList=[BOUNDARY_READ_ONLY],
        ActionNames=actions,
    )["EvaluationResults"]
    assert len(bounded_results) == len(actions), (
        f"expected one EvaluationResult per action, got {bounded_results}"
    )
    bounded = _by_action(bounded_results)

    inside = bounded["s3:GetObject"]
    assert inside["EvalDecision"] == "allowed", (
        "s3:GetObject is allowed by both the identity policy and the boundary, so the intersection "
        f"must be 'allowed'; got {inside['EvalDecision']!r}"
    )
    inside_detail = inside.get("PermissionsBoundaryDecisionDetail", {})
    assert inside_detail.get("AllowedByPermissionsBoundary") is True, (
        "an action inside the boundary must report AllowedByPermissionsBoundary=true; got "
        f"{inside_detail!r}"
    )

    outside = bounded["s3:DeleteObject"]
    assert outside["EvalDecision"] == "implicitDeny", (
        "s3:DeleteObject is allowed by the identity policy but absent from the boundary, so the "
        f"intersection must be 'implicitDeny'; got {outside['EvalDecision']!r}"
    )
    outside_detail = outside.get("PermissionsBoundaryDecisionDetail", {})
    assert outside_detail.get("AllowedByPermissionsBoundary", False) is False, (
        "an action outside the boundary must report AllowedByPermissionsBoundary=false; got "
        f"{outside_detail!r}"
    )

    # --- The boundary alone grants nothing: it can only subtract. An action the boundary allows
    # but the identity policy does not must still be implicitDeny.
    identity_silent = iam.simulate_custom_policy(
        PolicyInputList=[
            json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": "s3:DeleteObject", "Resource": "*"}
                    ],
                }
            )
        ],
        PermissionsBoundaryPolicyInputList=[BOUNDARY_READ_ONLY],
        ActionNames=["s3:ListBucket"],
    )["EvaluationResults"][0]
    assert identity_silent["EvalDecision"] == "implicitDeny", (
        "s3:ListBucket is in the boundary but not in the identity policy; a boundary must never "
        f"grant on its own. Expected 'implicitDeny', got {identity_silent['EvalDecision']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
