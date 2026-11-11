"""put-resource-policy-roundtrip-and-list."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-roundtrip-and-list"
GROUP = 'resource-policies'
SERVICES = ['xray']


def _account_id(ctx, xr):
    """The caller's account ID from a group ARN, creating a group if none exists.

    X-Ray resource policies validate that the principal exists, so a placeholder is rejected."""
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


def _delete_policy_if_present(xr, name):
    """Teardown: the check deletes the policy itself, so an already-absent policy is fine."""
    try:
        xr.delete_resource_policy(PolicyName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidRequestException":
            raise


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy returns a PolicyRevisionId and the document lists unchanged; after delete
    it is gone, and a second delete fails with InvalidRequestException without resurrecting it."""
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
    resp = xr.put_resource_policy(PolicyName=name, PolicyDocument=doc)
    ctx.on_cleanup(lambda: _delete_policy_if_present(xr, name))
    policy = resp["ResourcePolicy"]
    assert policy["PolicyName"] == name, f"expected PolicyName {name!r}, got {policy.get('PolicyName')!r}"
    assert policy.get("PolicyRevisionId"), "PolicyRevisionId not populated"

    listed = xr.list_resource_policies()["ResourcePolicies"]
    match = next((p for p in listed if p["PolicyName"] == name), None)
    assert match is not None, f"policy missing from ListResourcePolicies: {listed}"
    assert json.loads(match["PolicyDocument"]) == json.loads(doc), (
        f"listed PolicyDocument does not match what was written: got {match['PolicyDocument']!r}"
    )

    xr.delete_resource_policy(PolicyName=name)
    after_delete = [p["PolicyName"] for p in xr.list_resource_policies()["ResourcePolicies"]]
    assert name not in after_delete, f"deleted policy {name!r} still present in ListResourcePolicies: {after_delete}"

    try:
        xr.delete_resource_policy(PolicyName=name)
        raise AssertionError(
            f"expected a second delete of the already-deleted policy {name!r} to be rejected, "
            "but it returned success"
        )
    except ClientError as exc:
        error = exc.response.get("Error", {})
        assert error.get("Code") == "InvalidRequestException", (
            f"expected InvalidRequestException deleting an already-deleted policy, "
            f"got {error.get('Code')!r}: {error.get('Message')!r}"
        )
        assert error.get("Message") == f"The resource policy {name} does not exist.", (
            f"unexpected message: {error.get('Message')!r}"
        )
    after_second_delete = [p["PolicyName"] for p in xr.list_resource_policies()["ResourcePolicies"]]
    assert name not in after_second_delete, f"double-delete resurrected {name!r}: {after_second_delete}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
