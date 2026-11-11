"""check-no-new-access-fail-expanded-scope."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "check-no-new-access-fail-expanded-scope"
GROUP = "policy-analysis"
SERVICES = ["accessanalyzer"]


@tags("axis:happy-path", "cap:c7", "plane:control")
def run(ctx) -> None:
    """CheckNoNewAccess returns FAIL when the new policy grants access (s3:DeleteObject)
    that the existing policy did not grant."""
    aa = ctx.client("accessanalyzer")
    existing_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::sim2real-example-bucket/*",
        }],
    }
    new_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:DeleteObject"],
            "Resource": "arn:aws:s3:::sim2real-example-bucket/*",
        }],
    }
    resp = aa.check_no_new_access(
        newPolicyDocument=json.dumps(new_policy),
        existingPolicyDocument=json.dumps(existing_policy),
        policyType="IDENTITY_POLICY",
    )
    assert resp["result"] == "FAIL", resp


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
