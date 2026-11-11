"""delete-resource-policy-wrong-revision-fails."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-resource-policy-wrong-revision-fails"
GROUP = 'overly-permissive'
SERVICES = ['xray']


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, so a target that
    honours a stale revision fails here rather than on a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


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


def _safe_delete_policy(xr, name):
    """Teardown: the check deletes the policy itself, so an already-absent policy is clean."""
    try:
        xr.delete_resource_policy(PolicyName=name)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        not_found = ("InvalidRequestException", f"The resource policy {name} does not exist.")
        if (err.get("Code"), err.get("Message")) != not_found:
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResourcePolicy with a stale PolicyRevisionId fails with InvalidPolicyRevisionIdException
    (optimistic-concurrency boundary), the policy survives the failed delete unmutated, and a delete
    using the correct, current revision id still succeeds (positive control)."""
    xr = ctx.client("xray")
    name = ctx.unique_name("sim2real-behav-xray-policy-")
    doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowSegmentIngest",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{_account_id(ctx, xr)}:root"},
                    "Action": "xray:PutTraceSegments",
                    "Resource": "*",
                }
            ],
        }
    )
    first = xr.put_resource_policy(PolicyName=name, PolicyDocument=doc)["ResourcePolicy"]
    ctx.on_cleanup(lambda: _safe_delete_policy(xr, name))
    stale_revision = first["PolicyRevisionId"]

    # Advance the revision using the (currently valid) revision id, so stale_revision is a
    # genuinely-once-valid revision that is now out of date -- not a fabricated value.
    second = xr.put_resource_policy(
        PolicyName=name, PolicyDocument=doc, PolicyRevisionId=stale_revision
    )["ResourcePolicy"]
    current_revision = second["PolicyRevisionId"]
    assert current_revision != stale_revision, "PutResourcePolicy should mint a new revision id on each write"

    error = _client_error(
        lambda: xr.delete_resource_policy(PolicyName=name, PolicyRevisionId=stale_revision)
    )
    assert error.get("Code") == "InvalidPolicyRevisionIdException", (
        f"expected InvalidPolicyRevisionIdException, got {error!r}"
    )
    assert error.get("Message") == (
        f"Another concurrent request has modified or deleted the resource policy {name}"
    ), f"the refusal must name the policy, got {error!r}"

    listed = xr.list_resource_policies()["ResourcePolicies"]
    match = next((p for p in listed if p["PolicyName"] == name), None)
    assert match is not None, "policy removed despite failed delete"
    assert match["PolicyRevisionId"] == current_revision, "policy revision mutated by a rejected delete"

    # Positive control / restore: deleting with the correct, current revision succeeds.
    xr.delete_resource_policy(PolicyName=name, PolicyRevisionId=current_revision)
    listed_after = xr.list_resource_policies()["ResourcePolicies"]
    assert not any(p["PolicyName"] == name for p in listed_after), (
        "policy still listed after a correctly-revisioned delete"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
