"""get-buckets-aggregation-index-not-ready-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-buckets-aggregation-index-not-ready-rejected"
GROUP = "negative-classes"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """GetBucketsAggregation on a fleet index that is rebuilding fails with
    IndexNotReadyException, and once the index is ACTIVE the same call returns buckets
    and a totalCount."""
    iot = ctx.client("iot")

    aggregation_kwargs = dict(
        queryString="*",
        aggregationField="registry.thingTypeName",
        bucketsAggregationType={"termsAggregation": {"maxBuckets": 10}},
    )

    orig_cfg = iot.get_indexing_configuration().get(
        "thingIndexingConfiguration", {"thingIndexingMode": "OFF"}
    )
    ctx.on_cleanup(
        lambda: iot.update_indexing_configuration(thingIndexingConfiguration=orig_cfg)
    )

    _turn_indexing_off_and_wait(iot, timeout_s=60)
    iot.update_indexing_configuration(
        thingIndexingConfiguration={"thingIndexingMode": "REGISTRY"}
    )

    seen_not_ready = False
    race_deadline = time.monotonic() + 30
    while time.monotonic() < race_deadline:
        code = _race_attempt(lambda: iot.get_buckets_aggregation(**aggregation_kwargs))
        if code == "IndexNotReadyException":
            seen_not_ready = True
            break
        if code == "InvalidRequestException":
            # the REGISTRY schema for this new indexing configuration hasn't
            # finished registering yet -- transient, keep polling for either
            # IndexNotReadyException (BUILDING) or success (ACTIVE)
            time.sleep(0.2)
            continue
        if code != _SUCCEEDED:
            raise AssertionError(f"unexpected error before index was ready: {code}")
        # the call succeeded: the index was already ACTIVE by the time we got here -- race lost
        break


    active = _wait_index_active(iot, timeout_s=120)
    assert active, "AWS_Things index never became ACTIVE"

    # positive control: once ACTIVE, the identical call succeeds and returns
    # real aggregation data (not just a 200)
    result = iot.get_buckets_aggregation(**aggregation_kwargs)
    assert isinstance(result.get("buckets"), list), f"expected buckets: list, got {result.get('buckets')!r}"
    assert isinstance(result.get("totalCount"), int), f"expected totalCount: int, got {result.get('totalCount')!r}"

    if not seen_not_ready:
        raise AssertionError(
            "lost the race against the real UpdateIndexingConfiguration transition: "
            "the AWS_Things index reported ACTIVE before GetBucketsAggregation could "
            "observe it BUILDING, so IndexNotReadyException was never raised on this "
            "run; the positive-control path above was still exercised and asserted."
        )


_SUCCEEDED = "<call succeeded>"


def _race_attempt(fn):
    """One race probe: the error code, or ``_SUCCEEDED`` (a value no code can equal) when the
    call succeeds, which the race loop reads as a lost race."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    return _SUCCEEDED


def _turn_indexing_off_and_wait(iot, timeout_s: float) -> None:
    from botocore.exceptions import ClientError

    current = iot.get_indexing_configuration()
    mode = current.get("thingIndexingConfiguration", {}).get("thingIndexingMode", "OFF")
    if mode == "OFF":
        return
    iot.update_indexing_configuration(thingIndexingConfiguration={"thingIndexingMode": "OFF"})
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = iot.describe_index(indexName="AWS_Things")["indexStatus"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if status == "OFF":
            return
        time.sleep(1)
    raise AssertionError(f"AWS_Things index never reported OFF within {timeout_s}s")


def _wait_index_active(iot, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = iot.describe_index(indexName="AWS_Things")["indexStatus"]
        if status == "ACTIVE":
            return True
        time.sleep(2)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
