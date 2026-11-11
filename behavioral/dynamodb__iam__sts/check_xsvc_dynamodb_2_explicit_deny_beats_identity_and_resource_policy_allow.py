"""xsvc-dynamodb-2-explicit-deny-beats-identity-and-resource-policy-allow."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-dynamodb-2-explicit-deny-beats-identity-and-resource-policy-allow"
GROUP = "overly_permissive"
SERVICES = ["dynamodb", "iam", "sts"]

ERR_ACCESS_DENIED = "AccessDeniedException"
# AWS names the deciding layer in the message, the only thing that separates an EXPLICIT deny
# from an implicit one.
EXPLICIT_ATTRIBUTION = "with an explicit deny in a session policy"
IMPLICIT_ATTRIBUTION = "no identity-based policy allows"

#: A table resource policy is eventually consistent and exposes no "effective" condition; it can
#: take minutes to apply, and the check fails if it never takes effect within this bound.
_RP_BUDGET_S = 240

_PREFIX = "sim2real-xsvc-"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _denied(fn):
    """Call fn(); return (code, message) of the ClientError it raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    result = {k: v for k, v in (result or {}).items() if k != "ResponseMetadata"}
    raise AssertionError(f"call was expected to be DENIED but succeeded: {result!r}")


def _retry_denied(fn, *, timeout_s=90.0, interval_s=3.0, description="call"):
    """Retry fn() while it raises AccessDenied* (IAM/resource-policy propagation) -- bounded."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if not code.startswith("AccessDenied") or time.monotonic() >= deadline:
                raise AssertionError(
                    f"{description} still failing with {code!r} after {timeout_s}s: "
                    f"{exc.response.get('Error', {}).get('Message')!r}"
                ) from exc
        time.sleep(interval_s)


def _delete_role(iam, role_name):
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _delete_table(ddb, table):
    # A table that just had its resource policy deleted is briefly ResourceInUse (measured).
    deadline = time.monotonic() + 180
    while True:
        try:
            ddb.delete_table(TableName=table)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(5)


def _drop_resource_policy(ddb, arn):
    try:
        ddb.delete_resource_policy(ResourceArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "PolicyNotFoundException":
            raise


def _session_client(ctx, role_arn, session_policy=None):
    """A DynamoDB client for a fresh session of ``role_arn``, and the session's principal ARN."""
    sts = ctx.client("sts")
    kw = {"Policy": json.dumps(session_policy)} if session_policy else {}
    assumed = _retry_denied(
        lambda: sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=ctx.unique_name("sim2real-dn-")[:64],
            DurationSeconds=3600,
            **kw,
        ),
        timeout_s=_budget_s(ctx, 90.0),
        description="sts:AssumeRole on the freshly created role",
    )
    creds = assumed["Credentials"]
    client = ctx.client(
        "dynamodb",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return client, assumed["AssumedRoleUser"]["Arn"]


def _key(pk):
    return {"pk": {"S": pk}}


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """An explicit session-policy Deny beats both an identity-policy and a resource-policy Allow.

    GetItem is refused as an explicit deny for both roles after implicit-deny and Allow controls,
    while PutItem in the same denying session still succeeds.
    """
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    caller = ctx.client("sts").get_caller_identity()
    partition = caller["Arn"].split(":")[1]
    account = caller["Account"]

    table = ctx.unique_name(f"{_PREFIX}dn-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    table_arn = ddb.describe_table(TableName=table)["Table"]["TableArn"]
    ddb.put_item(TableName=table, Item={**_key("seed"), "v": {"S": "seed"}})

    trust = json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:{partition}:iam::{account}:root"},
        "Action": "sts:AssumeRole",
    }]})
    # Role A: granted by its IDENTITY policy.
    role_a = ctx.unique_name(f"{_PREFIX}dn-a-")
    arn_a = iam.create_role(RoleName=role_a, AssumeRolePolicyDocument=trust,
                            Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_a))
    iam.put_role_policy(RoleName=role_a, PolicyName="table-rw", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["dynamodb:GetItem", "dynamodb:PutItem"],
                       "Resource": table_arn}],
    }))
    # Role B: NO identity policy at all -- its only possible grant is the table resource policy.
    role_b = ctx.unique_name(f"{_PREFIX}dn-b-")
    arn_b = iam.create_role(RoleName=role_b, AssumeRolePolicyDocument=trust,
                            Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_b))

    # --- Control 1: B has no grant of its own, so it is IMPLICITLY denied ---------------------
    b_plain, b_principal = _session_client(ctx, arn_b)
    code, msg = _denied(lambda: b_plain.get_item(TableName=table, Key=_key("seed")))
    assert code == ERR_ACCESS_DENIED, f"B before the resource policy: got {code!r} ({msg!r})"
    expected_msg = (
        f"User: {b_principal} is not authorized to perform: dynamodb:GetItem on resource: "
        f"{table_arn} because {IMPLICIT_ATTRIBUTION} the dynamodb:GetItem action"
    )
    assert msg == expected_msg, f"B before the resource policy: expected {expected_msg!r}, got {msg!r}"
    assert IMPLICIT_ATTRIBUTION in msg and "explicit deny" not in msg, (
        f"B's refusal before the resource policy should be an implicit deny, got {msg!r}"
    )

    # --- Control 2: the table resource policy alone admits B ----------------------------------
    rp = {"Version": "2012-10-17", "Statement": [{
        "Sid": "AllowBothRoles",
        "Effect": "Allow",
        "Principal": {"AWS": [arn_a, arn_b]},
        "Action": ["dynamodb:GetItem", "dynamodb:PutItem"],
        "Resource": table_arn,
    }]}
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    while True:
        try:
            ddb.put_resource_policy(ResourceArn=table_arn, Policy=json.dumps(rp))
            break
        except ClientError as exc:
            # A just-created role can be rejected as an invalid principal until IAM converges.
            if exc.response["Error"]["Code"] != "ValidationException" or time.monotonic() >= deadline:
                raise
        time.sleep(5)
    ctx.on_cleanup(lambda: _drop_resource_policy(ddb, table_arn))
    got = _retry_denied(
        lambda: b_plain.get_item(TableName=table, Key=_key("seed"), ConsistentRead=True),
        timeout_s=_RP_BUDGET_S, interval_s=5.0,
        description="GetItem by role B through the table resource policy",
    )
    assert got.get("Item") == {**_key("seed"), "v": {"S": "seed"}}, (
        f"B's resource-policy read returned {got.get('Item')!r}"
    )

    allow_only = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["dynamodb:GetItem", "dynamodb:PutItem"],
         "Resource": table_arn},
    ]}
    with_deny = {"Version": "2012-10-17", "Statement": [
        *allow_only["Statement"],
        {"Effect": "Deny", "Action": "dynamodb:GetItem", "Resource": table_arn},
    ]}

    for label, role_arn in (("A(identity Allow)", arn_a), ("B(resource-policy Allow only)", arn_b)):
        # --- Control 3: an Allow-only session policy admits GetItem for this role -------------
        allowed, _ = _session_client(ctx, role_arn, allow_only)
        got = _retry_denied(
            lambda: allowed.get_item(TableName=table, Key=_key("seed"), ConsistentRead=True),
            timeout_s=_budget_s(ctx, 90.0),
            description=f"GetItem by {label} under an Allow-only session policy",
        )
        assert got.get("Item", {}).get("v") == {"S": "seed"}, f"{label}: got {got.get('Item')!r}"

        # --- The one broken thing: the same session policy plus an explicit Deny --------------
        denying, denying_principal = _session_client(ctx, role_arn, with_deny)
        code, msg = _denied(lambda: denying.get_item(TableName=table, Key=_key("seed")))
        assert code == ERR_ACCESS_DENIED, (
            f"{label}: explicit Deny should give {ERR_ACCESS_DENIED!r}, got {code!r} ({msg!r})"
        )
        expected_msg = (
            f"User: {denying_principal} is not authorized to perform: dynamodb:GetItem on "
            f"resource: {table_arn} {EXPLICIT_ATTRIBUTION}"
        )
        assert msg == expected_msg, f"{label}: expected {expected_msg!r}, got {msg!r}"
        assert EXPLICIT_ATTRIBUTION in msg, (
            f"{label}: the denial should be attributed to the explicit deny "
            f"(substring {EXPLICIT_ATTRIBUTION!r}), got {msg!r}"
        )
        # Positive control in the SAME denying session: the Deny names only GetItem.
        marker = f"written-by-{label[0]}"
        denying.put_item(TableName=table, Item={**_key(marker), "v": {"S": marker}})
        stored = ddb.get_item(TableName=table, Key=_key(marker), ConsistentRead=True).get("Item")
        assert stored == {**_key(marker), "v": {"S": marker}}, (
            f"{label}: PutItem in the denying session did not land: {stored!r}"
        )

    # --- invariant: the denied reads disturbed nothing ----------------------------------------
    seed = ddb.get_item(TableName=table, Key=_key("seed"), ConsistentRead=True).get("Item")
    assert seed == {**_key("seed"), "v": {"S": "seed"}}, f"seed item changed: {seed!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
