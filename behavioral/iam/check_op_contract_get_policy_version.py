"""op-contract-getPolicyVersion."""
from __future__ import annotations

import json
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getPolicyVersion"
GROUP = "error-semantics"
SERVICES = ["iam"]

POLICY_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}],
}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPolicyVersion returns the submitted document exactly as the default v1; a
    never-created v2, and v1 once the policy is deleted, fail with NoSuchEntity and the
    exact message."""
    iam = ctx.client("iam")
    policy_name = ctx.unique_name("sim2real-getpv-")
    arn = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=json.dumps(POLICY_DOC),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: _delete_if_present(iam, arn))

    version = iam.get_policy_version(PolicyArn=arn, VersionId="v1")["PolicyVersion"]
    assert version["IsDefaultVersion"] is True, f"expected v1 to be the default version, got {version}"
    doc = _policy_doc(version["Document"])
    assert doc == POLICY_DOC, f"expected {POLICY_DOC!r} byte-for-byte, got {doc!r}"

    code, message = _error(lambda: iam.get_policy_version(PolicyArn=arn, VersionId="v2"))
    assert code == "NoSuchEntity", f"expected NoSuchEntity for nonexistent version, got {code}"
    expected = f"Policy {arn} version v2 does not exist or is not attachable."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    iam.delete_policy(PolicyArn=arn)
    code_after_delete, message_after_delete = _error(lambda: iam.get_policy_version(PolicyArn=arn, VersionId="v1"))
    assert code_after_delete == "NoSuchEntity", (
        f"expected NoSuchEntity for v1 of a deleted policy, got {code_after_delete}"
    )
    expected_after_delete = f"Policy {arn} version v1 does not exist or is not attachable."
    assert message_after_delete == expected_after_delete, (
        f"expected message {expected_after_delete!r}, got {message_after_delete!r}"
    )


def _delete_if_present(iam, arn):
    try:
        iam.delete_policy(PolicyArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _policy_doc(doc):
    if isinstance(doc, dict):
        return doc
    return json.loads(urllib.parse.unquote(doc))


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
