"""batch-execute-statement-throttling-enforced."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-execute-statement-throttling-enforced"
GROUP = 'overly-permissive'
SERVICES = ['dynamodb']

_TAGS_KV = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

THROTTLE_CODES = {
    "ThrottlingException",
    "ProvisionedThroughputExceeded",
    "ProvisionedThroughputExceededException",
    "RequestLimitExceeded",
}


def _wait_table_active(ddb, table_name, timeout_s=90.0, interval_s=1.0):
    """Poll DescribeTable until the table AND every GSI on it report ACTIVE."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ddb.describe_table(TableName=table_name)["Table"]
        if last["TableStatus"] == "ACTIVE" and all(
            idx.get("IndexStatus", "ACTIVE") == "ACTIVE"
            for idx in last.get("GlobalSecondaryIndexes", [])
        ):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never went ACTIVE in {timeout_s}s: {last!r}")


def _simple_table(ddb, ctx, *, prefix="sim2real-behav-ddb-tbl-", billing_mode="PAY_PER_REQUEST",
                  provisioned_throughput=None):
    """Create a single-"pk" (S) hash-key table, register teardown, wait ACTIVE, return the name."""
    name = ctx.unique_name(prefix)
    kwargs = dict(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode=billing_mode,
        Tags=_TAGS_KV,
    )
    if billing_mode == "PROVISIONED":
        kwargs["ProvisionedThroughput"] = provisioned_throughput or {
            "ReadCapacityUnits": 5,
            "WriteCapacityUnits": 5,
        }
    ddb.create_table(**kwargs)
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    _wait_table_active(ddb, name)
    return name


def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent PartiQL INSERT batches against a 1-WCU table draw a throttling-class error, after
    a lone 2-statement control batch succeeds: BatchExecuteStatement enforces provisioned capacity.
    """
    ddb = ctx.client("dynamodb")
    name = _simple_table(
        ddb,
        ctx,
        billing_mode="PROVISIONED",
        provisioned_throughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
    )

    control = ddb.batch_execute_statement(Statements=[
        {
            "Statement": f'INSERT INTO "{name}" VALUE {{\'pk\': ?, \'v\': ?}}',
            "Parameters": [{"S": "control-0"}, {"S": "x"}],
        },
        {
            "Statement": f'INSERT INTO "{name}" VALUE {{\'pk\': ?, \'v\': ?}}',
            "Parameters": [{"S": "control-1"}, {"S": "x"}],
        },
    ])
    control_errors = [item["Error"] for item in control.get("Responses", []) if item.get("Error")]
    assert control_errors == [], (
        f"a lone unhurried 2-statement batch was rejected: {control_errors!r} -- the target "
        f"refuses BatchExecuteStatement outright, independent of load"
    )

    def _burst(wave: int, batch_idx: int):
        statements = [
            {
                "Statement": f'INSERT INTO "{name}" VALUE {{\'pk\': ?, \'v\': ?}}',
                "Parameters": [{"S": f"throttle-{wave}-{batch_idx}-{i}"}, {"S": "x" * 2000}],
            }
            for i in range(25)
        ]
        return ddb.batch_execute_statement(Statements=statements)

    def _wave(wave: int) -> set:
        results = _run_concurrent(
            [(lambda i=i: _burst(wave, i)) for i in range(16)], timeout_s=60
        )
        observed: set = set()
        for r in results:
            if isinstance(r, ClientError):
                observed.add(r.response.get("Error", {}).get("Code"))
            elif isinstance(r, BaseException):
                observed.add(type(r).__name__)
            elif isinstance(r, dict):
                for item in r.get("Responses", []):
                    err = item.get("Error")
                    if err:
                        observed.add(err.get("Code"))
        return observed

    observed = _wave(0)
    # A second wave, because a fresh table's burst credit can absorb the first one.
    if not (observed & THROTTLE_CODES):
        observed |= _wave(1)

    assert observed & THROTTLE_CODES, (
        f"expected server-side throttling under load against a 1-WCU table, "
        f"observed error codes: {observed}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
