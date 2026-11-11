"""create-delivery-missing-iam-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-delivery-missing-iam-permission-denied"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDelivery from a role denied logs:CreateDelivery raises AccessDeniedException, while
    an unrestricted principal (and the role once the deny is dropped) passes authorization and
    fails only on the nonexistent source."""
    logs = ctx.client("logs")
    sts = ctx.client("sts")

    caller_arn = sts.get_caller_identity()["Arn"]
    restricted_logs, assumed_arn, drop_deny = _build_denied_logs_client(ctx, caller_arn)

    source_name = ctx.unique_name("sim2real-behav-cdmp-src-")
    account = sts.get_caller_identity()["Account"]
    destination_arn = (
        f"arn:aws:logs:{ctx.region}:{account}:"
        f"delivery-destination:{ctx.unique_name('sim2real-behav-cdmp-dest-')}"
    )
    source_arn = f"arn:aws:logs:{ctx.region}:{account}:delivery-source:{source_name}"
    denied = (
        "AccessDeniedException",
        f"User: {assumed_arn} is not authorized to perform: logs:CreateDelivery on resource: "
        f"{source_arn} with an explicit deny in an identity-based policy",
    )
    not_found = ("ResourceNotFoundException", "Requested Delivery Destination does not exist in this account.")

    # IAM deny-policy propagation is eventually consistent; poll (bounded) until
    # the deny takes effect instead of asserting on the very first attempt.
    deadline = time.monotonic() + 45.0
    code = None
    while time.monotonic() < deadline:
        code = _error(
            lambda: restricted_logs.create_delivery(
                deliverySourceName=source_name, deliveryDestinationArn=destination_arn
            )
        )
        if code == denied:
            break
        time.sleep(3.0)
    assert code == denied, f"expected {denied!r}, got {code}"

    deliveries = logs.describe_deliveries().get("deliveries", [])
    assert source_name not in {d.get("deliverySourceName") for d in deliveries}, (
        f"CreateDelivery was denied, so no delivery for {source_name!r} may exist; "
        f"found sources {sorted(d.get('deliverySourceName') for d in deliveries)!r}"
    )

    # Positive control: the unrestricted principal passes authorization and fails on the
    # missing source, so the denial above is attributable to the IAM deny.
    control_code = _error(
        lambda: logs.create_delivery(
            deliverySourceName=source_name, deliveryDestinationArn=destination_arn
        )
    )
    assert control_code == not_found, (
        f"expected the unrestricted principal to pass authorization and hit "
        f"ResourceNotFoundException, got {control_code}"
    )

    # Dropping the deny must give the role the same outcome as the unrestricted control.
    drop_deny()
    deadline = time.monotonic() + 90.0
    restored_code = None
    while time.monotonic() < deadline:
        restored_code = _error(
            lambda: restricted_logs.create_delivery(
                deliverySourceName=source_name, deliveryDestinationArn=destination_arn
            )
        )
        if restored_code == not_found:
            break
        time.sleep(3.0)
    assert restored_code == not_found, (
        f"removing the deny must restore the same principal to the unrestricted control's "
        f"outcome (ResourceNotFoundException); got {restored_code}"
    )


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _drop_deny_policy(iam, role_name: str, policy_name: str) -> None:
    """Idempotent: the body may drop the deny before cleanup runs, so tolerate it being gone."""
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _build_denied_logs_client(ctx, caller_arn: str):
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    role_name = ctx.unique_name("sim2real-behav-cdmp-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": caller_arn}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # An explicit ALLOW is needed: without it IAM's implicit default-deny would also refuse the
    # call, so the AccessDeniedException could not be attributed to the explicit deny.
    allow_policy_name = "allow-create-delivery"
    allow_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "logs:CreateDelivery", "Resource": "*"}
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=allow_policy_name,
        PolicyDocument=json.dumps(allow_policy),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=allow_policy_name))

    policy_name = "deny-create-delivery"
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Deny", "Action": "logs:CreateDelivery", "Resource": "*"}
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(deny_policy),
    )
    ctx.on_cleanup(lambda: _drop_deny_policy(iam, role_name, policy_name))

    session_name = "sim2real-behav-cdmp-session"
    deadline = time.monotonic() + 30.0
    creds = None
    assumed_arn = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            creds = assumed["Credentials"]
            assumed_arn = assumed["AssumedRoleUser"]["Arn"]
            break
        except ClientError as err:
            last_err = err
            time.sleep(2.0)
    if creds is None:
        raise AssertionError(f"could not assume role in time: {last_err}")

    restricted_client = ctx.client(
        "logs",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return restricted_client, assumed_arn, lambda: _drop_deny_policy(iam, role_name, policy_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
