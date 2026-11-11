"""conditional-check-failed-requests-metric-counts-only-the-failures."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conditional-check-failed-requests-metric-counts-only-the-failures"
GROUP = 'telemetry'
SERVICES = ['dynamodb']

_NAMESPACE = 'AWS/DynamoDB'
_METRIC = 'ConditionalCheckFailedRequests'
_CAPACITY_METRIC = 'ConsumedWriteCapacityUnits'
_REFUSALS = 12
_SUCCESSES = 12
_METRIC_BUDGET_S = 900           # DynamoDB request metrics take minutes to publish
_POLL_INTERVAL_S = 2.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _error(fn):
    """The botocore error (Code, Message) for a call real AWS refuses. RAISES on unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(
        f'real AWS refuses this conditional write, but it SUCCEEDED and returned {result!r}'
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, description, ctx=None):
    """Poll probe() until predicate holds. Raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f'{description}: the run budget ended first; not graded')
    raise AssertionError(f'{description} not observed within {timeout_s}s; last saw {last!r}')


def _create_table(ctx, purpose):
    ddb = ctx.client('dynamodb')
    name = ctx.unique_name(f'sim2real-behav-ccf-{purpose}-')
    ddb.create_table(
        TableName=name,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real:managed', 'Value': 'true'},
              {'Key': 'sim2real:check', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter('table_exists').wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _stats(ctx, metric, dimensions, start, end):
    """get_metric_statistics Sum/SampleCount/Unit over a 60s-period window, flattened."""
    resp = ctx.client('cloudwatch').get_metric_statistics(
        Namespace=_NAMESPACE,
        MetricName=metric,
        Dimensions=[{'Name': k, 'Value': v} for k, v in dimensions],
        StartTime=start,
        EndTime=end,
        Period=60,
        Statistics=['Sum', 'SampleCount'],
    )
    points = resp['Datapoints']
    return {
        'sum': sum(p['Sum'] for p in points),
        'samples': sum(p['SampleCount'] for p in points),
        'units': sorted({p.get('Unit') for p in points}),
        'n_datapoints': len(points),
    }


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/metrics-dimensions.html
@tags("axis:happy-path", "cap:c2", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Each refused conditional PutItem counts once in ConditionalCheckFailedRequests (Unit Count,
    TableName dimension only), while successful conditional writes on a twin table whose capacity
    metric is live contribute nothing; the refusals leave the guard item unchanged.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/metrics-dimensions.html
    """
    ddb = ctx.client('dynamodb')

    # A window that starts BEFORE any traffic, so nothing this check causes can fall outside it.
    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)

    subject = _create_table(ctx, 'subject')
    control = _create_table(ctx, 'control')

    # The subject's guard item. Every refusal below is refused BECAUSE this exists.
    original = {'pk': {'S': 'lock'}, 'holder': {'S': 'first-writer'}, 'v': {'N': '1'}}
    ddb.put_item(TableName=subject, Item=original,
                 ConditionExpression='attribute_not_exists(pk)')

    # --- twin work, same instant, same request shape, opposite outcome ---
    for i in range(_REFUSALS):
        code, message = _error(lambda i=i: ddb.put_item(
            TableName=subject,
            Item={'pk': {'S': 'lock'}, 'holder': {'S': f'loser-{i}'}, 'v': {'N': '99'}},
            ConditionExpression='attribute_not_exists(pk)',
        ))
        assert code == 'ConditionalCheckFailedException', (
            f'refusal {i!r} of {_REFUSALS!r}: a PutItem guarded by attribute_not_exists(pk) against '
            f'an existing item must be refused with ConditionalCheckFailedException, got {code!r}'
        )
        assert message == 'The conditional request failed', (
            f'refusal {i!r} of {_REFUSALS!r}: expected the message '
            f"'The conditional request failed', got {message!r}"
        )
    control_capacity = 0.0
    for i in range(_SUCCESSES):
        resp = ddb.put_item(
            TableName=control,
            Item={'pk': {'S': f'fresh-{i}'}, 'holder': {'S': f'winner-{i}'}, 'v': {'N': '1'}},
            ConditionExpression='attribute_not_exists(pk)',
            ReturnConsumedCapacity='TOTAL',
        )
        control_capacity += resp['ConsumedCapacity']['CapacityUnits']
    assert control_capacity > 0, (
        f'the control leg must really have written: {_SUCCESSES!r} successful conditional PutItems '
        f'reported {control_capacity!r} total capacity units, expected > 0'
    )

    # --- the refusals must have written NOTHING.
    still = ddb.get_item(TableName=subject, Key={'pk': {'S': 'lock'}}, ConsistentRead=True)
    assert still.get('Item') == original, (
        f'{_REFUSALS!r} refused conditional PutItems must leave the guard item byte-identical; '
        f'GetItem returned {still.get("Item")!r}, expected {original!r}'
    )

    window_end = datetime.now(timezone.utc) + timedelta(minutes=1)

    # --- the subject's failures must be counted, exactly once each ---
    subject_stats = _poll_until(
        lambda: _stats(ctx, _METRIC, [('TableName', subject)], window_start, window_end),
        lambda s: s['sum'] >= _REFUSALS,
        timeout_s=_budget_s(ctx, _METRIC_BUDGET_S),
        ctx=ctx,
        interval_s=_POLL_INTERVAL_S,
        description=(
            f'{_NAMESPACE} {_METRIC} for TableName={subject} to publish a Sum of at least the '
            f'{_REFUSALS} refusals this check issued'
        ),
    )
    assert subject_stats['sum'] == float(_REFUSALS), (
        f'{_METRIC} must count REQUESTS refused, one per call: this check issued exactly '
        f'{_REFUSALS!r} refused conditional PutItems and {_SUCCESSES!r} successful ones on another '
        f'table, so the Sum for {subject} must be {float(_REFUSALS)!r}, got {subject_stats["sum"]!r} '
        f'over {subject_stats["n_datapoints"]!r} datapoints'
    )
    assert subject_stats['units'] == ['Count'], (
        f'{_METRIC} is a request counter and must be published with Unit "Count", got '
        f'{subject_stats["units"]!r}'
    )

    # --- the metric is dimensioned by TableName ALONE: an Operation-qualified query must be empty
    operation_qualified = _stats(
        ctx, _METRIC, [('TableName', subject), ('Operation', 'PutItem')],
        window_start, window_end,
    )
    assert operation_qualified['n_datapoints'] == 0, (
        f'{_METRIC} is documented with the TableName dimension only, so a query qualified with '
        f'Operation=PutItem must match no metric; got {operation_qualified["n_datapoints"]!r} '
        f'datapoints summing {operation_qualified["sum"]!r}'
    )

    # --- the control table: prove its metric pipeline is LIVE before demanding an absence ---
    control_capacity_stats = _poll_until(
        lambda: _stats(ctx, _CAPACITY_METRIC, [('TableName', control)],
                       window_start, window_end),
        lambda s: s['sum'] > 0,
        timeout_s=_budget_s(ctx, _METRIC_BUDGET_S),
        ctx=ctx,
        interval_s=_POLL_INTERVAL_S,
        description=(
            f'{_NAMESPACE} {_CAPACITY_METRIC} for the CONTROL table {control} to publish, which is '
            f'what makes the {_METRIC} absence below evidence rather than silence'
        ),
    )
    assert control_capacity_stats['sum'] > 0, (
        f'the control table published no write capacity, so nothing can be concluded from its '
        f'{_METRIC}: {control_capacity_stats!r}'
    )
    control_failures = _stats(ctx, _METRIC, [('TableName', control)],
                              window_start, window_end)
    assert control_failures['sum'] == 0.0, (
        f'{_SUCCESSES!r} conditional writes that all SUCCEEDED must contribute nothing to '
        f'{_METRIC}: {control} reports Sum {control_failures["sum"]!r} over '
        f'{control_failures["n_datapoints"]!r} datapoints, while its {_CAPACITY_METRIC} Sum is '
        f'{control_capacity_stats["sum"]!r} -- so the pipeline is live and the count is wrong'
    )

    # --- and the subject's count did not leak onto the control, nor vice versa: re-read the
    # --- subject once more and demand it is still exactly the refusal count (freeze on reads).
    subject_again = _stats(ctx, _METRIC, [('TableName', subject)], window_start, window_end)
    assert subject_again['sum'] == float(_REFUSALS), (
        f'reading a metric must not change it: {_METRIC} for {subject} was '
        f'{subject_stats["sum"]!r} and is now {subject_again["sum"]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
