"""conflict-exception-concurrent-state."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conflict-exception-concurrent-state"
GROUP = 'data-plane'
SERVICES = ['logs']


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore_missing(fn):
    """Teardown helper: run fn() and tolerate a ResourceNotFoundException (already deleted)."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _list_deliveries(svc):
    items: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"nextToken": token} if token else {}
        resp = svc.describe_deliveries(**kwargs)
        items.extend(resp.get("deliveries", []))
        token = resp.get("nextToken")
        if not token:
            break
    return items


def _describe_log_group(svc, name):
    desc = svc.describe_log_groups(logGroupNamePrefix=name)
    for g in desc.get("logGroups", []):
        if g["logGroupName"] == name:
            return g
    raise AssertionError(f"log group {name!r} not found via DescribeLogGroups")


def _create_source_bucket(ctx, s3, tag):
    name = ctx.unique_name(f"sim2real-behav-{tag}-")[:63].rstrip("-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _delete(_b=name):
        try:
            objs = s3.list_objects_v2(Bucket=_b).get("Contents", [])
            for o in objs:
                s3.delete_object(Bucket=_b, Key=o["Key"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        s3.delete_bucket(Bucket=_b)

    ctx.on_cleanup(_delete)
    return name


def _create_scheduled_query_role(ctx, iam, account, tag):
    role_name = ctx.unique_name(f"sim2real-behav-sqrole-{tag}-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "logs.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))

    def _delete_role(_n=role_name):
        try:
            for pname in iam.list_role_policies(RoleName=_n).get("PolicyNames", []):
                try:
                    iam.delete_role_policy(RoleName=_n, PolicyName=pname)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=_n)

    ctx.on_cleanup(_delete_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="allow-scheduled-query",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["logs:StartQuery", "logs:GetQueryResults", "logs:StopQuery"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    return f"arn:aws:iam::{account}:role/{role_name}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A duplicate scheduled-query name or deleting a still-attached delivery destination raises
    ConflictException and leaves state intact; a repeat CreateDelivery for the same pair upserts."""
    svc = ctx.client("logs")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # -- delivery pipeline: duplicate-link + destination-still-attached conflicts.
    bucket = _create_source_bucket(ctx, s3, "dlvconflict")
    source_name = ctx.unique_name("sim2real-behav-dlvsrc-")
    svc.put_delivery_source(
        name=source_name, resourceArn=f"arn:aws:s3:::{bucket}", logType="S3_SERVER_ACCESS_LOGS"
    )
    ctx.on_cleanup(lambda _n=source_name: _ignore_missing(lambda: svc.delete_delivery_source(name=_n)))

    target_group = ctx.unique_name("sim2real-behav-lg-dlvconflict-")
    svc.create_log_group(logGroupName=target_group)
    ctx.on_cleanup(lambda _n=target_group: svc.delete_log_group(logGroupName=_n))
    target_arn = _describe_log_group(svc, target_group)["logGroupArn"]

    dest_name = ctx.unique_name("sim2real-behav-dlvdst-")
    dest_resp = svc.put_delivery_destination(
        name=dest_name,
        deliveryDestinationType="CWL",
        deliveryDestinationConfiguration={"destinationResourceArn": target_arn},
    )
    ctx.on_cleanup(lambda _n=dest_name: _ignore_missing(lambda: svc.delete_delivery_destination(name=_n)))
    dest_arn = dest_resp["deliveryDestination"]["arn"]

    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowLogDeliveryActions",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                    "Action": "logs:CreateDelivery",
                    "Resource": [
                        f"arn:aws:logs:{ctx.region}:{account}:delivery-source:*",
                        f"arn:aws:logs:{ctx.region}:{account}:delivery:*",
                        f"arn:aws:logs:{ctx.region}:{account}:delivery-destination:*",
                    ],
                },
            ],
        }
    )
    svc.put_delivery_destination_policy(deliveryDestinationName=dest_name, deliveryDestinationPolicy=policy_doc)
    got_policy = svc.get_delivery_destination_policy(deliveryDestinationName=dest_name)
    got_policy_doc = json.loads(got_policy["policy"]["deliveryDestinationPolicy"])
    assert got_policy_doc == json.loads(policy_doc), (
        f"expected the destination policy to round-trip byte-for-byte (as parsed JSON), "
        f"put {json.loads(policy_doc)!r}, got {got_policy_doc!r}"
    )
    svc.delete_delivery_destination_policy(deliveryDestinationName=dest_name)

    first = svc.create_delivery(deliverySourceName=source_name, deliveryDestinationArn=dest_arn)
    delivery_id = first["delivery"]["id"]
    ctx.on_cleanup(lambda _i=delivery_id: _ignore_missing(lambda: svc.delete_delivery(id=_i)))

    # A second CreateDelivery for the same source+destination pair does not conflict:
    # CreateDelivery is an upsert that returns the existing delivery id.
    second = svc.create_delivery(deliverySourceName=source_name, deliveryDestinationArn=dest_arn)
    second_delivery_id = second["delivery"]["id"]
    assert second_delivery_id == delivery_id, (
        f"expected a second CreateDelivery for the same source+destination to idempotently return the "
        f"SAME delivery id {delivery_id!r}, got a different id {second_delivery_id!r}"
    )

    deliveries_for_pair = [
        d
        for d in _list_deliveries(svc)
        if d.get("deliverySourceName") == source_name and d.get("deliveryDestinationArn") == dest_arn
    ]
    assert len(deliveries_for_pair) == 1, (
        f"expected exactly one delivery for this source+destination pair after the idempotent "
        f"re-pairing, found {len(deliveries_for_pair)}: {deliveries_for_pair!r}"
    )

    base_fields = first["delivery"].get("recordFields", [])
    extra_field = "bucket_arn"
    new_fields = base_fields if extra_field in base_fields else base_fields + [extra_field]
    svc.update_delivery_configuration(id=delivery_id, recordFields=new_fields)
    updated = svc.get_delivery(id=delivery_id)
    assert updated["delivery"].get("recordFields") == new_fields, "UpdateDeliveryConfiguration was not reflected"

    code, msg = _error(lambda: svc.delete_delivery_destination(name=dest_name))
    assert code == "ConflictException", (
        f"expected DeleteDeliveryDestination to be rejected while a delivery is still attached, "
        f"got {code!r} {msg!r}"
    )
    assert msg == (
        "Could not delete this Delivery Destination as it is currently in use. Please delete any "
        "Deliveries that reference this resource and try again."
    ), f"unexpected DeleteDeliveryDestination in-use message: {msg!r}"

    still_there = svc.get_delivery_destination(name=dest_name)["deliveryDestination"]
    assert still_there["name"] == dest_name and still_there["arn"] == dest_arn, (
        f"expected the delivery destination to be unaffected by the rejected delete, got {still_there!r}"
    )

    svc.delete_delivery(id=delivery_id)
    svc.delete_delivery_destination(name=dest_name)
    svc.delete_delivery_source(name=source_name)

    # -- scheduled queries: duplicate-name conflict.
    sq_group = ctx.unique_name("sim2real-behav-lg-sqconflict-")
    svc.create_log_group(logGroupName=sq_group)
    ctx.on_cleanup(lambda _n=sq_group: svc.delete_log_group(logGroupName=_n))
    sq_group_arn = _describe_log_group(svc, sq_group)["logGroupArn"]

    role_arn = _create_scheduled_query_role(ctx, iam, account, "conflict")
    name = ctx.unique_name("sim2real-behav-sq-conflict-")
    common = dict(
        queryLanguage="CWLI",
        queryString="fields @timestamp, @message | limit 10",
        scheduleExpression="cron(0 12 * * ? *)",
        startTimeOffset=3600,
        executionRoleArn=role_arn,
        logGroupIdentifiers=[sq_group_arn],
    )
    svc.create_scheduled_query(name=name, state="ENABLED", **common)
    ctx.on_cleanup(lambda _n=name: _ignore_missing(lambda: svc.delete_scheduled_query(identifier=_n)))

    code, msg = _error(
        lambda: svc.create_scheduled_query(
            name=name, state="ENABLED", **{**common, "queryString": "fields @timestamp | limit 1"}
        )
    )
    assert code == "ConflictException", (
        f"expected a duplicate-name CreateScheduledQuery to be rejected with ConflictException, "
        f"got {code!r} {msg!r}"
    )
    assert msg == f"Scheduled query with identifier {name} already exists", (
        f"unexpected duplicate-name CreateScheduledQuery message: {msg!r}"
    )

    # The rejected duplicate used a different queryString, so a same-name overwrite would show here.
    untouched = svc.get_scheduled_query(identifier=name)
    assert untouched["state"] == "ENABLED" and untouched["queryString"] == common["queryString"], (
        f"expected the rejected duplicate CreateScheduledQuery to leave the original scheduled "
        f"query untouched, got {untouched!r}"
    )

    svc.update_scheduled_query(identifier=name, state="DISABLED", **common)
    got_sq = svc.get_scheduled_query(identifier=name)
    assert got_sq["state"] == "DISABLED", f"expected UpdateScheduledQuery to take effect, got {got_sq.get('state')!r}"

    svc.delete_scheduled_query(identifier=name)

    fake_source_arn = f"arn:aws:cloudtrail:{ctx.region}:{account}:eventdatastore/{ctx.unique_name('')}"
    fake_role_arn = f"arn:aws:iam::{account}:role/{ctx.unique_name('sim2real-behav-importrole-')}"
    code, msg = _error(
        lambda: svc.create_import_task(importSourceArn=fake_source_arn, importRoleArn=fake_role_arn)
    )
    assert code == "InvalidParameterException", (
        f"expected CreateImportTask against a nonexistent source to be rejected with "
        f"InvalidParameterException, got {code!r} {msg!r}"
    )
    assert msg == f"Invalid Event Data Store ARN: {fake_source_arn}", (
        f"unexpected CreateImportTask message for a nonexistent source: {msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
