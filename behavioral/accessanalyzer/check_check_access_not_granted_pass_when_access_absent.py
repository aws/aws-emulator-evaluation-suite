"""check-access-not-granted-pass-when-access-absent."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "check-access-not-granted-pass-when-access-absent"
GROUP = "policy-analysis"
SERVICES = ["accessanalyzer"]


@tags("axis:happy-path", "cap:c7", "plane:control")
def run(ctx) -> None:
    """CheckAccessNotGranted returns PASS when the identity policy genuinely does not
    grant any of the checked actions/resources."""
    aa = ctx.client("accessanalyzer")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::sim2real-example-bucket/*",
        }],
    }
    resp = aa.check_access_not_granted(
        policyDocument=json.dumps(policy),
        access=[{"actions": ["s3:PutObject"], "resources": ["arn:aws:s3:::sim2real-example-bucket/*"]}],
        policyType="IDENTITY_POLICY",
    )
    assert resp["result"] == "PASS", f"expected PASS, got {resp['result']}: {resp.get('reasons')}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
