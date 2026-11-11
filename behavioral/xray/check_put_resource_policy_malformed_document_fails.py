"""put-resource-policy-malformed-document-fails."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-malformed-document-fails"
GROUP = 'overly-permissive'
SERVICES = ['xray']


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a document real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected PutResourcePolicy to be rejected, but it SUCCEEDED: {result!r}")


def _account_id(ctx, xr):
    """Derive the caller's account ID from a group ARN (X-Ray resource policies validate the
    principal exists, so a placeholder account is rejected). Stays within the service under
    test rather than relying on STS. Creates a group if none exists, registering its cleanup."""
    arn = None
    for group in xr.get_groups().get("Groups", []):
        if group.get("GroupARN"):
            arn = group["GroupARN"]
            break
    if not arn:
        name = ctx.unique_name("sim2real-behav-xray-acct-")
        arn = xr.create_group(GroupName=name, FilterExpression='service("default")')["Group"]["GroupARN"]
        ctx.on_cleanup(lambda: xr.delete_group(GroupName=name))
    # arn:aws:xray:<region>:<account-id>:group/<name>/<id>
    return arn.split(":")[4]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy refuses a non-JSON PolicyDocument with MalformedPolicyDocumentException
    carrying no message and persists nothing, while a well-formed document is accepted."""
    xr = ctx.client("xray")
    account_id = _account_id(ctx, xr)

    # Positive control: a well-formed document is accepted.
    good_name = ctx.unique_name("sim2real-behav-xray-policy-good-")
    good_document = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowSegmentIngest",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "xray:PutTraceSegments",
                    "Resource": "*",
                }
            ],
        }
    )
    xr.put_resource_policy(PolicyName=good_name, PolicyDocument=good_document)
    ctx.on_cleanup(lambda: xr.delete_resource_policy(PolicyName=good_name))

    name = ctx.unique_name("sim2real-behav-xray-policy-bad-")
    error = _error(
        lambda: xr.put_resource_policy(PolicyName=name, PolicyDocument="{this is not json or a policy}")
    )
    assert error.get("Code") == "MalformedPolicyDocumentException", f"got {error!r}"
    # AWS refuses this document with a bare error type and no message at all.
    message = error.get("Message") or ""
    assert message == "", f"expected no message, got {message!r}"

    listed = xr.list_resource_policies()["ResourcePolicies"]
    assert not any(p["PolicyName"] == name for p in listed), "malformed policy was persisted"
    assert any(p["PolicyName"] == good_name for p in listed), "positive-control policy is missing"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
