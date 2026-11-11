"""validate-policy-flags-wildcard-security-warning."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "validate-policy-flags-wildcard-security-warning"
GROUP = "policy-analysis"
SERVICES = ["accessanalyzer"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ValidatePolicy flags iam:PassRole on a wildcard Resource with a SECURITY_WARNING
    PASS_ROLE_WITH_STAR_IN_RESOURCE finding, and the same action on a specific role ARN gets no
    such finding, so the detection keys on the wildcard."""
    aa = ctx.client("accessanalyzer")
    wildcard_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "*",
        }],
    }
    resp = aa.validate_policy(policyDocument=json.dumps(wildcard_policy), policyType="IDENTITY_POLICY")
    matches = [f for f in resp["findings"] if f["issueCode"] == "PASS_ROLE_WITH_STAR_IN_RESOURCE"]
    assert matches, f"expected PASS_ROLE_WITH_STAR_IN_RESOURCE finding, got {resp['findings']}"
    assert matches[0]["findingType"] == "SECURITY_WARNING", matches[0]

    scoped_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "arn:aws:iam::123456789012:role/example-role",
        }],
    }
    resp2 = aa.validate_policy(policyDocument=json.dumps(scoped_policy), policyType="IDENTITY_POLICY")
    scoped_matches = [f for f in resp2["findings"] if f["issueCode"] == "PASS_ROLE_WITH_STAR_IN_RESOURCE"]
    assert not scoped_matches, (
        "expected no PASS_ROLE_WITH_STAR_IN_RESOURCE finding for a resource-scoped "
        f"PassRole, got {scoped_matches}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
