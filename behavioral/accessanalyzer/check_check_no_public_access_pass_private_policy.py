"""check-no-public-access-pass-private-policy."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "check-no-public-access-pass-private-policy"
GROUP = "policy-analysis"
SERVICES = ["accessanalyzer"]


@tags("axis:happy-path", "cap:c7", "plane:control")
def run(ctx) -> None:
    """CheckNoPublicAccess returns PASS for a resource policy scoped to a specific
    account principal (no public access)."""
    aa = ctx.client("accessanalyzer")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::sim2real-example-bucket/*",
        }],
    }
    resp = aa.check_no_public_access(policyDocument=json.dumps(policy), resourceType="AWS::S3::Bucket")
    assert resp["result"] == "PASS", resp


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
