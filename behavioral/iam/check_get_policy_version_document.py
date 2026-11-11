"""get-policy-version-document."""
from __future__ import annotations

import json

from behavioral_harness import tags

MINIMAL_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "iam:GetUser",
            "Resource": "arn:aws:iam::*:user/sim2real-behav-*",
        }
    ],
}

CHECK = "get-policy-version-document"
GROUP = 'policy_lifecycle'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPolicyVersion on the default version (v1) returns the exact document
    submitted at CreatePolicy, byte-for-byte as JSON, and marks it IsDefaultVersion=True."""
    iam = ctx.client("iam")
    arn = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-behav-pol-"),
        PolicyDocument=json.dumps(MINIMAL_POLICY_DOCUMENT),
        Path="/",
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda a=arn: iam.delete_policy(PolicyArn=a))
    resp = iam.get_policy_version(PolicyArn=arn, VersionId="v1")
    version = resp["PolicyVersion"]
    doc = version["Document"]
    # Document may be URL-encoded or a dict depending on boto3/emulator
    if isinstance(doc, str):
        from urllib.parse import unquote

        doc = json.loads(unquote(doc))
    assert doc == MINIMAL_POLICY_DOCUMENT, f"expected document {MINIMAL_POLICY_DOCUMENT!r}, got {doc!r}"
    assert version["VersionId"] == "v1", f"expected VersionId 'v1', got {version['VersionId']!r}"
    assert version["IsDefaultVersion"] is True, f"expected IsDefaultVersion True, got {version['IsDefaultVersion']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
