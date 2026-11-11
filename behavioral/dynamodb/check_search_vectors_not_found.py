"""search-vectors-not-found."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "search-vectors-not-found"
GROUP = 'errors'
SERVICES = ['dynamodb']
ERR_NOT_FOUND = 'ResourceNotFoundException'


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError('expected a ClientError, call unexpectedly succeeded')


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'condition not met within {timeout_s}s, last value: {last!r}')


def _delete_table_ignore(ddb, table_name: str) -> None:
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SearchVectors on a nonexistent table raises ResourceNotFoundException ("Requested resource not found") instead
    of an empty result, while on a real table with an 8-dimension vector index it returns results.
    """
    ddb = ctx.client('dynamodb')
    index_name = 'vec-idx'
    table_name = ctx.unique_name('sim2real-behav-svnf-')
    vector = [{'N': '0.0'}] * 8

    try:
        ddb.create_table(
            TableName=table_name,
            AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
            KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
            BillingMode='PAY_PER_REQUEST',
            Tags=[{'Key': 'sim2real', 'Value': CHECK}],
            VectorIndexes=[
                {
                    'IndexName': index_name,
                    'Dimensions': 8,
                    'DistanceFunction': 'EUCLIDEAN',
                    'Projection': {'ProjectionType': 'ALL'},
                    'VectorAttribute': {'AttributeName': 'Embedding'},
                }
            ],
        )
    except (ClientError, TypeError) as err:
        raise AssertionError(f'vector indexes not available in this account/region/SDK: {err}')
    ctx.on_cleanup(lambda: _delete_table_ignore(ddb, table_name))

    described = _poll_until(
        lambda: ddb.describe_table(TableName=table_name)['Table'],
        lambda t: t['TableStatus'] == 'ACTIVE'
        and t.get('VectorIndexes')
        and t['VectorIndexes'][0]['IndexStatus'] == 'ACTIVE',
        timeout_s=300,
        interval_s=5,
    )
    described_dims = described['VectorIndexes'][0]['Dimensions']
    assert described_dims == 8, f'expected vector index dimensions 8, got {described_dims}'

    ddb.put_item(TableName=table_name, Item={'pk': {'S': 'near'}, 'Embedding': {'L': vector}})

    # Positive control: SearchVectors against the real table+index it just wrote to succeeds.
    positive = _poll_until(
        lambda: ddb.search_vectors(
            TableName=table_name,
            IndexName=index_name,
            SearchVector=vector,
            TopK=1,
        )['SearchResults'],
        lambda r: len(r) >= 1,
        timeout_s=180,
        interval_s=5,
    )
    assert positive, 'positive control returned no results against a table it just wrote to'

    missing = table_name + '-absent'
    code, message = _error_code(
        lambda: ddb.search_vectors(
            TableName=missing,
            IndexName=index_name,
            SearchVector=vector,
            TopK=1,
        )
    )
    assert code == ERR_NOT_FOUND, f'expected {ERR_NOT_FOUND}, got {code}'
    assert message == "Requested resource not found", (
        f"expected AWS's exact ResourceNotFoundException message, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
