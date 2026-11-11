"""xsvc-logs-3-s3-access-log-delivery-denied-without-destination-grant."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-logs-3-s3-access-log-delivery-denied-without-destination-grant"
GROUP = "vended-delivery"
SERVICES = ["logs", "s3"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDelivery from an S3_SERVER_ACCESS_LOGS source is refused (AccessDeniedException) for a
    caller denied only logs:PutResourcePolicy, leaving no delivery and no grant on the destination
    group; lifting that one deny makes the same session's identical call succeed.
    """
    logs = ctx.client("logs")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-xsvc-sal-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    group = ctx.unique_name("/sim2real/xsvc-sal-lg-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    group_arn = f"arn:aws:logs:{ctx.region}:{account}:log-group:{group}"

    source = ctx.unique_name("sim2real-xsvc-sal-src-")
    src = logs.put_delivery_source(
        name=source, resourceArn=f"arn:aws:s3:::{bucket}", logType="S3_SERVER_ACCESS_LOGS"
    )["deliverySource"]
    ctx.on_cleanup(lambda: logs.delete_delivery_source(name=source))
    assert src.get("service") == "s3" and src.get("resourceArns") == [f"arn:aws:s3:::{bucket}"], (
        f"delivery source does not name the bucket: {src!r}"
    )
    dest_name = ctx.unique_name("sim2real-xsvc-sal-dst-")
    dest = logs.put_delivery_destination(
        name=dest_name, deliveryDestinationConfiguration={"destinationResourceArn": group_arn}
    )["deliveryDestination"]
    ctx.on_cleanup(lambda: logs.delete_delivery_destination(name=dest_name))
    assert dest.get("deliveryDestinationType") == "CWL", f"destination type was {dest!r}"
    dest_arn = dest["arn"]

    restricted, drop_deny = _restricted_logs_client(ctx, iam, sts)

    # Barrier: the role's ALLOW is effective (a read on the same source succeeds), so a
    # denial below is attributable to the deny statement, not to IAM propagation.
    _poll_until(
        lambda: _ok(lambda: restricted.get_delivery_source(name=source)),
        bool, timeout_s=90.0, interval_s=3.0,
        description="the restricted session can read the delivery source",
    )

    # Registered BEFORE the first create: any delivery to our destination -- a wrongly accepted
    # refusal or the repaired call below -- is reaped before the destination itself.
    ctx.on_cleanup(lambda: _delete_deliveries_to(logs, dest_arn))
    code, message = _error(lambda: restricted.create_delivery(
        deliverySourceName=source, deliveryDestinationArn=dest_arn
    ))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r} ({message!r})"
    want_denial = (
        "Access Denied for this Delivery Destination. Please make sure that you have correct "
        "permissions to access the Log Destination Resource."
    )
    assert message == want_denial, f"expected the denial {want_denial!r}, got {message!r}"

    # Effect absent: no delivery to our destination, and no grant on our group.
    assert _deliveries_to(logs, dest_arn) == [], (
        f"a refused CreateDelivery left a delivery behind: {_deliveries_to(logs, dest_arn)!r}"
    )
    assert _group_policies(logs, group_arn) == [], (
        f"a refused CreateDelivery left a resource policy on {group}: "
        f"{_group_policies(logs, group_arn)!r}"
    )

    # Repair exactly the one thing: drop the deny. The SAME session's identical call succeeds.
    drop_deny()

    def _attempt():
        try:
            return restricted.create_delivery(
                deliverySourceName=source, deliveryDestinationArn=dest_arn
            )["delivery"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            return None

    delivery = _poll_until(_attempt, lambda d: d is not None, timeout_s=120.0, interval_s=5.0,
                           description="CreateDelivery succeeds once the deny is lifted")
    assert delivery.get("deliverySourceName") == source, f"delivery was {delivery!r}"
    assert delivery.get("deliveryDestinationArn") == dest_arn, f"delivery was {delivery!r}"
    assert delivery.get("deliveryDestinationType") == "CWL", f"delivery was {delivery!r}"
    listed = [d["id"] for d in _deliveries_to(logs, dest_arn)]
    assert listed == [delivery["id"]], f"deliveries to our destination: {listed!r}"


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate() holds; RAISE on the deadline (never return last)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _ok(fn) -> bool:
    try:
        fn()
        return True
    except ClientError:
        return False


def _error(fn):
    """(code, message) of the ClientError. An unexpected SUCCESS raises rather than becoming a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message") or ""
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _deliveries_to(logs, dest_arn: str) -> list[dict]:
    out: list[dict] = []
    kwargs: dict = {}
    while True:
        page = logs.describe_deliveries(**kwargs)
        out.extend(d for d in page.get("deliveries", []) if d.get("deliveryDestinationArn") == dest_arn)
        if not page.get("nextToken"):
            return out
        kwargs["nextToken"] = page["nextToken"]


def _delete_deliveries_to(logs, dest_arn: str) -> None:
    for d in _deliveries_to(logs, dest_arn):
        try:
            logs.delete_delivery(id=d["id"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise


def _group_policies(logs, group_arn: str) -> list[dict]:
    return logs.describe_resource_policies(
        resourceArn=group_arn, policyScope="RESOURCE"
    ).get("resourcePolicies", [])


def _restricted_logs_client(ctx, iam, sts):
    caller_arn = sts.get_caller_identity()["Arn"]
    role_name = ctx.unique_name("sim2real-xsvc-sal-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"AWS": caller_arn}, "Action": "sts:AssumeRole"}
            ],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # An explicit ALLOW for every logs action: without it the denial could be IAM's implicit
    # default-deny, and the repair below could not attribute anything to the one deny.
    iam.put_role_policy(
        RoleName=role_name, PolicyName="allow-logs",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "logs:*", "Resource": "*"}]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="allow-logs"))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="deny-put-resource-policy",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Deny", "Action": "logs:PutResourcePolicy", "Resource": "*"}]}),
    )

    def _drop_deny():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="deny-put-resource-policy")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_drop_deny)

    # IAM propagation exposes no pollable condition for AssumeRole on a new role; the bounded
    # retry is what makes this correct.
    creds = _poll_until(
        lambda: _try_assume(sts, role_arn), lambda c: c is not None,
        timeout_s=60.0, interval_s=3.0, description=f"AssumeRole on {role_arn}",
    )
    client = ctx.client("logs", creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })
    return client, _drop_deny


def _try_assume(sts, role_arn: str):
    try:
        return sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-xsvc-sal")["Credentials"]
    except ClientError:
        return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
