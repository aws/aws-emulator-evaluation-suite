"""check-access-not-granted-invalid-parameter-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "check-access-not-granted-invalid-parameter-rejected"
GROUP = "overly-permissive"
SERVICES = ["accessanalyzer"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CheckAccessNotGranted rejects an access entry with neither actions nor resources with
    ValidationException, while a well-formed entry against the same policy still evaluates."""
    aa = ctx.client("accessanalyzer")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::sim2real-example-bucket/*",
        }],
    }
    policy_document = json.dumps(policy)

    code, message = _error(
        lambda: aa.check_access_not_granted(
            policyDocument=policy_document,
            access=[{"actions": [], "resources": []}],
            policyType="IDENTITY_POLICY",
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == "The access object must have at least one action or one resource.", message

    resp = aa.check_access_not_granted(
        policyDocument=policy_document,
        access=[{"actions": ["s3:DeleteObject"], "resources": ["arn:aws:s3:::sim2real-example-bucket/*"]}],
        policyType="IDENTITY_POLICY",
    )
    assert resp["result"] == "PASS", resp


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so a target
    accepting what AWS refuses cannot be read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
