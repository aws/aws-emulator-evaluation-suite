"""validate-policy-malformed-json-reported-as-error-finding."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "validate-policy-malformed-json-reported-as-error-finding"
GROUP = "overly-permissive"
SERVICES = ["accessanalyzer"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ValidatePolicy answers a policyDocument that is not valid JSON with an ERROR finding in a 200
    response rather than an exception, while a valid policy returns no such parse error."""
    aa = ctx.client("accessanalyzer")

    resp = aa.validate_policy(policyDocument="{this is not valid json", policyType="IDENTITY_POLICY")
    findings = resp["findings"]
    error_findings = [f for f in findings if f["findingType"] == "ERROR"]
    assert error_findings, f"expected an ERROR-type finding for malformed JSON, got findings={findings}"
    assert any(f["issueCode"] == "JSON_SYNTAX_ERROR" for f in error_findings), (
        f"expected issueCode=JSON_SYNTAX_ERROR for malformed JSON, got error_findings={error_findings}"
    )

    valid_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::sim2real-bucket/*"}],
    }
    resp2 = aa.validate_policy(policyDocument=json.dumps(valid_policy), policyType="IDENTITY_POLICY")
    assert isinstance(resp2["findings"], list), f"expected findings to be a list, got {resp2['findings']!r}"
    assert not any(f["findingType"] == "ERROR" for f in resp2["findings"]), resp2["findings"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

