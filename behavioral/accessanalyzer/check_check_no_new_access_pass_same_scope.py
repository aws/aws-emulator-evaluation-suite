"""check-no-new-access-pass-same-scope."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "check-no-new-access-pass-same-scope"
GROUP = "policy-analysis"
SERVICES = ["accessanalyzer"]


@tags("axis:happy-path", "cap:c7", "plane:control")
def run(ctx) -> None:
    """CheckNoNewAccess returns PASS when the new policy grants no more access than the
    existing policy (here, an identical policy)."""
    aa = ctx.client("accessanalyzer")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::sim2real-example-bucket/*",
        }],
    }
    resp = aa.check_no_new_access(
        newPolicyDocument=json.dumps(policy),
        existingPolicyDocument=json.dumps(policy),
        policyType="IDENTITY_POLICY",
    )
    assert resp["result"] == "PASS", resp


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
