"""put-resource-policy-optimistic-lock-fails."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-optimistic-lock-fails"
GROUP = 'overly-permissive'
SERVICES = ['xray']


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the stale-revision call to be rejected, but it SUCCEEDED and returned {result!r}")


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


def _policy_document(account_id, sid=None):
    statement = {
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
        "Action": "xray:PutTraceSegments",
        "Resource": "*",
    }
    if sid:
        statement["Sid"] = sid
    return json.dumps({"Version": "2012-10-17", "Statement": [statement]})


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stale PolicyRevisionId makes PutResourcePolicy and DeleteResourcePolicy fail with
    InvalidPolicyRevisionIdException naming the policy, leaving document and revision unmoved; a
    Put with the current revision succeeds."""
    xr = ctx.client("xray")
    account_id = _account_id(ctx, xr)
    name = ctx.unique_name("sim2real-behav-xray-policy-")
    first = xr.put_resource_policy(
        PolicyName=name, PolicyDocument=_policy_document(account_id)
    )["ResourcePolicy"]
    ctx.on_cleanup(lambda: xr.delete_resource_policy(PolicyName=name))
    stale_revision = first["PolicyRevisionId"]

    # Advance the revision using the (currently valid) revision id. This is now the positive
    # control: PutResourcePolicy with the correct revision works.
    advanced = xr.put_resource_policy(
        PolicyName=name,
        PolicyDocument=_policy_document(account_id, sid="Advance"),
        PolicyRevisionId=stale_revision,
    )["ResourcePolicy"]
    current_revision = advanced["PolicyRevisionId"]
    assert current_revision != stale_revision, "revision did not advance on a valid Put"

    # stale_revision is now out of date; using it for either Put or Delete must fail the lock.
    put_code, put_message = _error(
        lambda: xr.put_resource_policy(
            PolicyName=name,
            PolicyDocument=_policy_document(account_id, sid="Stale"),
            PolicyRevisionId=stale_revision,
        )
    )
    assert put_code == "InvalidPolicyRevisionIdException", (
        f"expected InvalidPolicyRevisionIdException, got {put_code}"
    )
    assert put_message == f"Another concurrent request has modified the resource policy {name}", (
        f"unexpected message: {put_message!r}"
    )

    delete_code, delete_message = _error(
        lambda: xr.delete_resource_policy(PolicyName=name, PolicyRevisionId=stale_revision)
    )
    assert delete_code == "InvalidPolicyRevisionIdException", (
        f"expected InvalidPolicyRevisionIdException, got {delete_code}"
    )
    assert delete_message == (
        f"Another concurrent request has modified or deleted the resource policy {name}"
    ), f"unexpected message: {delete_message!r}"

    # Independent read at the destination: neither rejected call touched the stored policy.
    listed = xr.list_resource_policies()["ResourcePolicies"]
    match = next((p for p in listed if p["PolicyName"] == name), None)
    assert match is not None, "policy removed despite a failed stale-revision delete"
    assert match["PolicyRevisionId"] == current_revision, (
        f"revision moved by a rejected stale Put: expected {current_revision}, got {match['PolicyRevisionId']}"
    )
    assert json.loads(match["PolicyDocument"]) == json.loads(_policy_document(account_id, sid="Advance")), (
        "rejected stale Put mutated the stored document"
    )

    # Restore: the identical Put succeeds once it carries the CURRENT revision.
    restored = xr.put_resource_policy(
        PolicyName=name,
        PolicyDocument=_policy_document(account_id, sid="Restored"),
        PolicyRevisionId=current_revision,
    )["ResourcePolicy"]
    assert restored["PolicyRevisionId"] != current_revision, "revision did not advance on the restore Put"

    final = xr.list_resource_policies()["ResourcePolicies"]
    final_match = next((p for p in final if p["PolicyName"] == name), None)
    assert final_match is not None, "policy missing after the restore Put"
    assert json.loads(final_match["PolicyDocument"]) == json.loads(_policy_document(account_id, sid="Restored")), (
        "restore Put did not persist the new document"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
