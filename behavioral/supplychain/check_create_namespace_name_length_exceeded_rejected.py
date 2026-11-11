"""create-namespace-name-length-exceeded-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-namespace-name-length-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["supplychain"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDataLakeNamespace rejects a name longer than the documented 50-character limit
    with ValidationException, no namespace is created, and a name at/under the limit for the
    same instance succeeds and is independently readable back through GetDataLakeNamespace."""
    # AWS Supply Chain is not offered in us-west-2 (CreateInstance answers ValidationException
    # "Amazon Connect Decisions is not supported in us-west-2"); pin to a region where it runs.
    sc = ctx.client("supplychain", region="us-east-1")
    instance_id = _create_active_instance(ctx, sc)

    namespaces_before = sc.list_data_lake_namespaces(instanceId=instance_id)["namespaces"]

    too_long_name = ("a" * 51)
    code, message = _error(
        lambda: sc.create_data_lake_namespace(instanceId=instance_id, name=too_long_name)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        "1 validation error detected: Value at 'name' failed to satisfy constraint: "
        "Member must have length less than or equal to 50"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    namespaces_after = sc.list_data_lake_namespaces(instanceId=instance_id)["namespaces"]
    assert len(namespaces_after) == len(namespaces_before), (
        "a namespace appears to have been created despite the rejected over-length name"
    )

    valid_name = _dl_name(ctx, "ns")
    assert len(valid_name) <= 50, f"positive-control name {valid_name!r} exceeds the 50-char limit"
    created = sc.create_data_lake_namespace(
        instanceId=instance_id, name=valid_name, tags={"sim2real": "true"}
    )["namespace"]
    ctx.on_cleanup(
        lambda: _best_effort(lambda: sc.delete_data_lake_namespace(instanceId=instance_id, name=valid_name))
    )
    assert created["name"] == valid_name, f"expected {valid_name!r}, got {created['name']!r}"

    fetched = sc.get_data_lake_namespace(instanceId=instance_id, name=valid_name)["namespace"]
    assert fetched["name"] == valid_name, (
        f"independent read of {valid_name!r} returned name {fetched['name']!r}"
    )
    assert fetched["arn"] == created["arn"], (
        f"independent read arn {fetched['arn']!r} != create response arn {created['arn']!r}"
    )


def _dl_name(ctx, kind):
    raw = ctx.unique_name(f"sim2real-sc-{kind}-")
    return raw.lower().replace("-", "").replace(".", "")[:50]


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return its ClientError code and message. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_active_instance(ctx, sc):
    name = ctx.unique_name("sim2real-sc-")
    instance = sc.create_instance(
        instanceName=name,
        instanceDescription="sim2real behavioral check",
        tags={"sim2real": "true"},
    )["instance"]
    instance_id = instance["instanceId"]

    def _cleanup():
        try:
            sc.delete_instance(instanceId=instance_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    result = _poll_until(
        lambda: sc.get_instance(instanceId=instance_id)["instance"],
        lambda inst: inst["state"] in ("Active", "CreateFailed"),
        timeout_s=1200.0,
        interval_s=15.0,
    )
    if result["state"] != "Active":
        raise AssertionError(f"instance did not reach Active state: {result}")
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
