"""resource-policy-malformed-json-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-malformed-json-rejected"
GROUP = "error-semantics"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy with malformed JSON is rejected with InvalidPolicyFault "The resource policy
    can't be parsed.", GetResourcePolicy then answers ResourceNotFoundFault, and a well-formed policy
    on the same namespace is stored as sent."""
    redshift = ctx.client("redshift")
    rss = ctx.client("redshift-serverless")

    ns_name = ctx.unique_name("sim2real-polbad-ns-")
    ns = rss.create_namespace(
        namespaceName=ns_name,
        tags=[{"key": "sim2real", "value": CHECK}],
    )["namespace"]
    ctx.on_cleanup(lambda: rss.delete_namespace(namespaceName=ns_name))
    _poll_until(
        lambda: rss.get_namespace(namespaceName=ns_name)["namespace"]["status"],
        lambda status: status == "AVAILABLE",
        timeout_s=300,
        interval_s=5,
    )
    namespace_arn = ns["namespaceArn"]

    malformed = '{"Version": "2012-10-17", "Statement": [ { "Effect": "Allow", ] }'  # broken

    code, message = _error(
        lambda: redshift.put_resource_policy(ResourceArn=namespace_arn, Policy=malformed)
    )
    assert code == "InvalidPolicyFault", f"expected InvalidPolicyFault, got {code!r}"
    expected_message = "The resource policy can't be parsed."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    absent_code, absent_message = _error(
        lambda: redshift.get_resource_policy(ResourceArn=namespace_arn)
    )
    assert absent_code == "ResourceNotFoundFault", "a policy was stored despite malformed JSON"
    expected_absent = "The requested resource policy doesn\u2019t exist."
    assert absent_message == expected_absent, (
        f"expected message {expected_absent!r}, got {absent_message!r}"
    )

    # Positive control: a well-formed policy on the same resource still works.
    valid_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "redshift.amazonaws.com"},
                "Action": "redshift:AuthorizeInboundIntegration",
                "Resource": namespace_arn,
                "Condition": {"StringEquals": {"aws:SourceArn": "arn:aws:dynamodb:*:*:table/*"}},
            }
        ],
    }
    redshift.put_resource_policy(ResourceArn=namespace_arn, Policy=json.dumps(valid_policy))
    ctx.on_cleanup(lambda: redshift.delete_resource_policy(ResourceArn=namespace_arn))
    stored = redshift.get_resource_policy(ResourceArn=namespace_arn)["ResourcePolicy"]["Policy"]
    stored_doc = json.loads(stored)
    assert stored_doc == valid_policy, f"expected stored policy {valid_policy!r}, got {stored_doc!r}"


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    import time

    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, so a target that accepts a call real AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
