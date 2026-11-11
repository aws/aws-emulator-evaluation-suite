"""put-resource-policy-nonexistent-resource-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-resource-policy-nonexistent-resource-rejected"
GROUP = "error-semantics"
SERVICES = ["comprehend"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy and DescribeResourcePolicy on a nonexistent ResourceArn fail with
    ResourceNotFoundException and exact messages, while ListDocumentClassifiers succeeds as a control."""
    comprehend = ctx.client("comprehend")
    account_id = _account_id(ctx)
    fake_arn = (
        f"arn:aws:comprehend:{ctx.region}:{account_id}:"
        f"document-classifier/{ctx.unique_name('sim2real-put-policy-')}"
    )
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "comprehend:ImportModel",
                "Resource": fake_arn,
            }
        ],
    }

    # Sanity control: an unrelated, normal Comprehend call still succeeds under these
    # credentials.
    listed = comprehend.list_document_classifiers()
    assert "DocumentClassifierPropertiesList" in listed, (
        f"expected a normal ListDocumentClassifiers call to succeed, got {listed!r}"
    )

    code, message = _error(
        lambda: comprehend.put_resource_policy(
            ResourceArn=fake_arn, ResourcePolicy=json.dumps(policy)
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected PutResourcePolicy on a nonexistent resource to be rejected with "
        f"ResourceNotFoundException, got {code!r}"
    )
    expected = "RESOURCE_NOT_FOUND: Could not find specified resource."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Independent read at a different operation: no policy is attached to the (still
    # nonexistent) resource.
    describe_code, message = _error(
        lambda: comprehend.describe_resource_policy(ResourceArn=fake_arn)
    )
    assert describe_code == "ResourceNotFoundException", (
        f"expected DescribeResourcePolicy on the same resource to also report "
        f"ResourceNotFoundException (no policy was attached), got {describe_code!r}"
    )
    expected = "RESOURCE_NOT_FOUND: Could not find specified resource."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
