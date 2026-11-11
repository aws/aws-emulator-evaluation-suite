"""check-no-public-access-fail-public-policy."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "check-no-public-access-fail-public-policy"
GROUP = "policy-analysis"
SERVICES = ["accessanalyzer"]


@tags("axis:happy-path", "cap:c7", "plane:control")
def run(ctx) -> None:
    """CheckNoPublicAccess returns FAIL for a resource policy that grants Principal "*"
    access to the resource."""
    aa = ctx.client("accessanalyzer")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::sim2real-example-bucket/*",
        }],
    }
    resp = aa.check_no_public_access(policyDocument=json.dumps(policy), resourceType="AWS::S3::Bucket")
    assert resp["result"] == "FAIL", resp
    reasons = resp.get("reasons") or []
    assert reasons, f"expected non-empty reasons explaining the FAIL verdict, got {resp!r}"
    assert all(r["statementIndex"] == 0 for r in reasons), (
        f"expected every reason to cite the sole policy statement (index 0), got {reasons!r}"
    )
    assert all(r["description"] for r in reasons), f"expected a non-empty description per reason, got {reasons!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
