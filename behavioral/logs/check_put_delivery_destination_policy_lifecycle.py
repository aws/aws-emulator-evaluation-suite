"""put-delivery-destination-policy-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


CHECK = "put-delivery-destination-policy-lifecycle"
GROUP = 'delivery'
SERVICES = ['logs']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDeliveryDestinationPolicy attaches a policy GetDeliveryDestinationPolicy returns; after
    DeleteDeliveryDestinationPolicy, Get returns none, a second delete gets ResourceNotFoundException
    with its message, and the destination remains.
    """
    svc = ctx.client("logs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    target_group = ctx.unique_name("sim2real-behav-lg-dlvpol-")
    svc.create_log_group(logGroupName=target_group)
    ctx.on_cleanup(lambda _n=target_group: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=target_group: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))
    target_arn = svc.describe_log_groups(logGroupNamePrefix=target_group)["logGroups"][0]["logGroupArn"]

    dest_name = ctx.unique_name("sim2real-behav-dlvdstpol-")
    svc.put_delivery_destination(
        name=dest_name,
        deliveryDestinationType="CWL",
        deliveryDestinationConfiguration={"destinationResourceArn": target_arn},
    )
    ctx.on_cleanup(lambda _n=dest_name: svc.delete_delivery_destination(name=_n))
    ctx.on_cleanup(
        lambda _n=dest_name: _ignore_not_found(
            lambda: svc.delete_delivery_destination_policy(deliveryDestinationName=_n)
        )
    )

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
    svc.put_delivery_destination_policy(
        deliveryDestinationName=dest_name, deliveryDestinationPolicy=policy_doc
    )

    got = svc.get_delivery_destination_policy(deliveryDestinationName=dest_name)
    sids = {s["Sid"] for s in json.loads(got["policy"]["deliveryDestinationPolicy"])["Statement"]}
    assert sids == {"AllowLogDeliveryActions"}, f"unexpected policy round-trip: {sids!r}"

    svc.delete_delivery_destination_policy(deliveryDestinationName=dest_name)

    # a destination with no policy attached is a plain empty-get, not a 404 -- so the terminal state
    # here is the same empty shape, not a ResourceNotFoundException.
    def _post_delete_policy():
        return svc.get_delivery_destination_policy(deliveryDestinationName=dest_name)["policy"].get(
            "deliveryDestinationPolicy"
        )

    remaining = _poll_until(
        _post_delete_policy,
        lambda p: not p,
        timeout_s=30,
        interval_s=2.0,
        description="delivery destination policy cleared to empty after delete",
    )
    assert not remaining, f"policy still present after delete: {remaining!r}"

    # the policy is dead, not just absent from one read: deleting it again raises the same
    # ResourceNotFoundException a destination that never had a policy would give, never a
    # resurfaced document or a silent no-op success.
    try:
        svc.delete_delivery_destination_policy(deliveryDestinationName=dest_name)
        raise AssertionError("expected ResourceNotFoundException re-deleting an already-absent policy")
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got_err = (err.get("Code"), err.get("Message"))
        assert got_err == ("ResourceNotFoundException", "Delivery Destination Policy does not exist for this Delivery Destination."), (
            f"expected ResourceNotFoundException re-deleting an already-absent policy, got {got_err!r}"
        )

    # the destination itself must survive the policy's deletion.
    still_there = svc.get_delivery_destination(name=dest_name)
    assert still_there["deliveryDestination"]["name"] == dest_name


def _ignore_not_found(fn):
    """Teardown wrapper: the check deletes this resource itself, so a teardown that finds it
    already gone is the expected outcome, not a leak."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
