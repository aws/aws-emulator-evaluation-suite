"""select-all-projected-attributes-requires-an-index-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "select-all-projected-attributes-requires-an-index-rejected"
GROUP = 'query'
SERVICES = ['dynamodb']

ERR_VALIDATION = 'ValidationException'
_INDEX = 'keys-only-index'


def _code(fn):
    """The error code and message *fn* raises; an unexpected success fails loudly instead."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'real AWS refuses this call, but it SUCCEEDED and returned {result!r}')


def _poll_until_count(fn, want, ctx):
    """*fn*'s result once its Count reaches *want*, bounded by the check's own time budget.

    A GSI is updated asynchronously from the base table it indexes, so a query against it right
    after the put may still lag; this is the one bounded wait that is legitimate here.
    """
    _GSI_POLL_BUDGET_S = 30.0
    time_left = ctx.time_left()
    budget = _GSI_POLL_BUDGET_S if time_left is None else min(_GSI_POLL_BUDGET_S, time_left)
    deadline = time.monotonic() + budget
    result = fn()
    while result.get('Count', 0) != want and time.monotonic() < deadline:
        time.sleep(1.0)
        result = fn()
    return result


_CONFLICT_MESSAGE = {
    'ALL_ATTRIBUTES': (
        '1 validation error detected: Cannot specify the ProjectionExpression when choosing to '
        'get ALL_ATTRIBUTES'
    ),
    'COUNT': (
        '1 validation error detected: Cannot specify the ProjectionExpression when choosing to '
        'get only the Count'
    ),
    'ALL_PROJECTED_ATTRIBUTES': (
        '1 validation error detected: Cannot specify the ProjectionExpression when choosing to '
        'get ALL_PROJECTED_ATTRIBUTES'
    ),
}


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Select is validated against the rest of a Query or Scan request -- a missing IndexName or
    ProjectionExpression, a KEYS_ONLY index, or a ProjectionExpression paired with any Select
    other than SPECIFIC_ATTRIBUTES -- while each legal combination still succeeds.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-select-')
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {'AttributeName': 'pk', 'KeyType': 'HASH'},
            {'AttributeName': 'sk', 'KeyType': 'RANGE'},
        ],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'gsi_pk', 'AttributeType': 'S'},
        ],
        GlobalSecondaryIndexes=[{
            'IndexName': _INDEX,
            'KeySchema': [{'AttributeName': 'gsi_pk', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'KEYS_ONLY'},
        }],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=table, Item={
        'pk': {'S': 'P'}, 'sk': {'S': 'S'}, 'gsi_pk': {'S': 'G'}, 'body': {'S': 'payload'},
    })

    base = {
        'TableName': table,
        'KeyConditionExpression': 'pk = :p',
        'ExpressionAttributeValues': {':p': {'S': 'P'}},
    }
    on_index = {
        'TableName': table,
        'IndexName': _INDEX,
        'KeyConditionExpression': 'gsi_pk = :g',
        'ExpressionAttributeValues': {':g': {'S': 'G'}},
    }

    # --- ALL_PROJECTED_ATTRIBUTES names an index's projection and needs an index ---
    code, message = _code(lambda: ddb.query(**base, Select='ALL_PROJECTED_ATTRIBUTES'))
    assert code == ERR_VALIDATION, (
        f'Select=ALL_PROJECTED_ATTRIBUTES refers to an index projection and must be refused with '
        f'{ERR_VALIDATION} when no IndexName accompanies it; got {code}'
    )
    assert message == "1 validation error detected: ALL_PROJECTED_ATTRIBUTES can be used only when Querying using an IndexName", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )
    projected = _poll_until_count(
        lambda: ddb.query(**on_index, Select='ALL_PROJECTED_ATTRIBUTES'), 1, ctx,
    )
    assert projected['Count'] == 1, (
        f'the same Select value WITH an IndexName is legal and must return the indexed item, got '
        f'{projected!r}'
    )

    # --- SPECIFIC_ATTRIBUTES needs something to be specific about ---
    code, message = _code(lambda: ddb.query(**base, Select='SPECIFIC_ATTRIBUTES'))
    assert code == ERR_VALIDATION, (
        f'Select=SPECIFIC_ATTRIBUTES with no ProjectionExpression names no attributes and must be '
        f'refused with {ERR_VALIDATION}; got {code}'
    )
    assert message == "1 validation error detected: Must specify the AttributesToGet or ProjectionExpression when choosing to get SPECIFIC_ATTRIBUTES", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )
    specific = ddb.query(**base, Select='SPECIFIC_ATTRIBUTES', ProjectionExpression='body')
    assert specific['Items'] == [{'body': {'S': 'payload'}}], (
        f'the same Select value WITH a ProjectionExpression is legal and must return only that '
        f'attribute, got {specific["Items"]!r}'
    )

    # --- ALL_ATTRIBUTES cannot be served from a KEYS_ONLY index ---
    code, message = _code(lambda: ddb.query(**on_index, Select='ALL_ATTRIBUTES'))
    assert code == ERR_VALIDATION, (
        f'Select=ALL_ATTRIBUTES against a KEYS_ONLY index asks for attributes the index does not '
        f'hold and must be refused with {ERR_VALIDATION} rather than served from the base table; '
        f'got {code}'
    )
    assert message == f"One or more parameter values were invalid: Select type ALL_ATTRIBUTES is not supported for global secondary index {on_index['IndexName']} because its projection type is not ALL", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )
    all_attrs = ddb.query(**base, Select='ALL_ATTRIBUTES', ConsistentRead=True)
    assert all_attrs['Items'] == [{
        'pk': {'S': 'P'}, 'sk': {'S': 'S'}, 'gsi_pk': {'S': 'G'}, 'body': {'S': 'payload'},
    }], (
        f'the same Select value against the BASE table is legal and must return the whole item, got '
        f'{all_attrs["Items"]!r}'
    )

    # --- Select + ProjectionExpression is a disallowed combination on Query, for every Select
    # value other than SPECIFIC_ATTRIBUTES (already proven legal above) ---
    for select in ('ALL_ATTRIBUTES', 'COUNT'):
        code, message = _code(lambda select=select: ddb.query(
            **base, Select=select, ProjectionExpression='body',
        ))
        assert code == ERR_VALIDATION, (
            f'Select={select} together with a ProjectionExpression on Query must be refused with '
            f'{ERR_VALIDATION}; got {code}'
        )
        assert message == _CONFLICT_MESSAGE[select], (
            f"expected AWS's exact ValidationException message for Select={select}+"
            f"ProjectionExpression on Query, got {message!r}"
        )

    code, message = _code(lambda: ddb.query(
        **on_index, Select='ALL_PROJECTED_ATTRIBUTES', ProjectionExpression='body',
    ))
    assert code == ERR_VALIDATION, (
        f'Select=ALL_PROJECTED_ATTRIBUTES together with a ProjectionExpression on Query must be '
        f'refused with {ERR_VALIDATION} even though an IndexName is present; got {code}'
    )
    assert message == _CONFLICT_MESSAGE['ALL_PROJECTED_ATTRIBUTES'], (
        f"expected AWS's exact ValidationException message for Select=ALL_PROJECTED_ATTRIBUTES+"
        f"ProjectionExpression on Query, got {message!r}"
    )

    count_query = ddb.query(**base, Select='COUNT', ConsistentRead=True)
    assert count_query['Count'] == 1, (
        f'Select=COUNT with no ProjectionExpression is legal on Query and must count the item, '
        f'got {count_query!r}'
    )

    # --- the same conflict class holds on Scan: this validation is not pinned to Query alone ---
    base_scan = {'TableName': table}
    on_index_scan = {'TableName': table, 'IndexName': _INDEX}

    for select in ('ALL_ATTRIBUTES', 'COUNT'):
        code, message = _code(lambda select=select: ddb.scan(
            **base_scan, Select=select, ProjectionExpression='body',
        ))
        assert code == ERR_VALIDATION, (
            f'Select={select} together with a ProjectionExpression on Scan must be refused with '
            f'{ERR_VALIDATION}; got {code}'
        )
        assert message == _CONFLICT_MESSAGE[select], (
            f"expected AWS's exact ValidationException message for Select={select}+"
            f"ProjectionExpression on Scan, got {message!r}"
        )

    code, message = _code(lambda: ddb.scan(
        **on_index_scan, Select='ALL_PROJECTED_ATTRIBUTES', ProjectionExpression='body',
    ))
    assert code == ERR_VALIDATION, (
        f'Select=ALL_PROJECTED_ATTRIBUTES together with a ProjectionExpression on Scan must be '
        f'refused with {ERR_VALIDATION} even though an IndexName is present; got {code}'
    )
    assert message == _CONFLICT_MESSAGE['ALL_PROJECTED_ATTRIBUTES'], (
        f"expected AWS's exact ValidationException message for Select=ALL_PROJECTED_ATTRIBUTES+"
        f"ProjectionExpression on Scan, got {message!r}"
    )

    # Positive controls: each Select value with no ProjectionExpression remains legal on Scan.
    all_attrs_scan = ddb.scan(**base_scan, Select='ALL_ATTRIBUTES', ConsistentRead=True)
    assert all_attrs_scan['Items'] == [{
        'pk': {'S': 'P'}, 'sk': {'S': 'S'}, 'gsi_pk': {'S': 'G'}, 'body': {'S': 'payload'},
    }], (
        f'Select=ALL_ATTRIBUTES with no ProjectionExpression is legal on a base-table Scan, got '
        f'{all_attrs_scan["Items"]!r}'
    )
    count_scan = ddb.scan(**base_scan, Select='COUNT', ConsistentRead=True)
    assert count_scan['Count'] == 1, (
        f'Select=COUNT with no ProjectionExpression is legal on Scan and must count the item, got '
        f'{count_scan!r}'
    )
    projected_scan = _poll_until_count(
        lambda: ddb.scan(**on_index_scan, Select='ALL_PROJECTED_ATTRIBUTES'), 1, ctx,
    )
    assert projected_scan['Items'] == [{
        'sk': {'S': 'S'}, 'pk': {'S': 'P'}, 'gsi_pk': {'S': 'G'},
    }], (
        f'Select=ALL_PROJECTED_ATTRIBUTES with no ProjectionExpression is legal on a Scan of the '
        f'index, got {projected_scan["Items"]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
