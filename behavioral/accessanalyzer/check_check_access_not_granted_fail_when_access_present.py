"""check-access-not-granted-fail-when-access-present."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "check-access-not-granted-fail-when-access-present"
GROUP = "policy-analysis"
SERVICES = ["accessanalyzer"]


@tags("axis:happy-path", "cap:c7", "plane:control")
def run(ctx) -> None:
    """CheckAccessNotGranted returns FAIL when the identity policy DOES grant one of the
    checked actions on the checked resource."""
    aa = ctx.client("accessanalyzer")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "arn:aws:s3:::sim2real-example-bucket/*",
        }],
    }
    resp = aa.check_access_not_granted(
        policyDocument=json.dumps(policy),
        access=[{"actions": ["s3:PutObject"], "resources": ["arn:aws:s3:::sim2real-example-bucket/*"]}],
        policyType="IDENTITY_POLICY",
    )
    assert resp["result"] == "FAIL", resp
    reasons = resp["reasons"]
    assert reasons, f"expected reasons to explain the FAIL, got {resp}"
    assert reasons[0]["statementIndex"] == 0, (
        f"expected the reason to point at statement 0 (the only statement), got {resp}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
