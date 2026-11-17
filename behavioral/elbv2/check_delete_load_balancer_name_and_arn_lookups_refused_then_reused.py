"""delete-load-balancer-name-and-arn-lookups-refused-then-reused."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-load-balancer-name-and-arn-lookups-refused-then-reused"
GROUP = "load-balancer-lifecycle"
SERVICES = ["elbv2"]

_NOT_FOUND = ("LoadBalancerNotFound",)


def _teardown(undo, *not_found: str):
    """Undo via ``undo()``; only the resource's own not-found codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _refused(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=90.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last was {last!r}")
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteLoadBalancer, both the by-name and by-ARN lookups are refused with their own
    not-found messages, and the freed name claims a new load balancer with a fresh ARN.
    """
    elb = ctx.client("elbv2")
    subnet_ids = ctx.network().subnet_ids[:2]
    name = ctx.unique_name("sim2real-behav-lb-")[:32].rstrip("-")

    def _create():
        return elb.create_load_balancer(
            Name=name, Subnets=subnet_ids, Type="application", Scheme="internal",
            Tags=[{"Key": "sim2real", "Value": "elbv2-lb-lifecycle"}],
        )["LoadBalancers"][0]

    created = _create()
    old_arn = created["LoadBalancerArn"]
    ctx.on_cleanup(_teardown(lambda: elb.delete_load_balancer(LoadBalancerArn=old_arn), *_NOT_FOUND))

    elb.delete_load_balancer(LoadBalancerArn=old_arn)

    def probe_by_name():
        try:
            return _refused(lambda: elb.describe_load_balancers(Names=[name]))
        except AssertionError:
            return None

    name_code, name_message = _poll_until(
        probe_by_name, lambda r: r is not None,
        description="by-name lookup refused after delete",
    )
    assert name_code == "LoadBalancerNotFound", f"expected LoadBalancerNotFound, got {name_code!r}"
    assert name_message == f"Load balancers '[{name}]' not found", f"unexpected message {name_message!r}"

    def probe_by_arn():
        try:
            return _refused(lambda: elb.describe_load_balancers(LoadBalancerArns=[old_arn]))
        except AssertionError:
            return None

    arn_code, arn_message = _poll_until(
        probe_by_arn, lambda r: r is not None,
        description="by-arn lookup refused after delete",
    )
    assert arn_code == "LoadBalancerNotFound", f"expected LoadBalancerNotFound, got {arn_code!r}"
    assert arn_message == "One or more load balancers not found", f"unexpected message {arn_message!r}"

    def try_recreate():
        try:
            return _create()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "DuplicateLoadBalancerName":
                raise
            return code

    recreated = _poll_until(
        try_recreate, lambda r: not isinstance(r, str),
        description="freed name becoming claimable again",
    )
    new_arn = recreated["LoadBalancerArn"]
    ctx.on_cleanup(_teardown(lambda: elb.delete_load_balancer(LoadBalancerArn=new_arn), *_NOT_FOUND))
    assert recreated["LoadBalancerName"] == name, f"recreated name was {recreated['LoadBalancerName']!r}"
    assert new_arn != old_arn, "recreated load balancer must not carry the deleted one's ARN"

    def by_name_after_recreate():
        try:
            resp = elb.describe_load_balancers(Names=[name])["LoadBalancers"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                raise
            return []
        return [lb["LoadBalancerArn"] for lb in resp]

    arns = _poll_until(
        by_name_after_recreate, lambda a: a == [new_arn],
        description="by-name lookup resolving to the recreated load balancer's ARN",
    )
    assert arns == [new_arn], f"by-name lookup returned {arns!r}, expected exactly [{new_arn!r}]"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
