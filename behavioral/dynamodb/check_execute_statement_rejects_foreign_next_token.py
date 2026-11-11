"""execute-statement-rejects-foreign-next-token."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-rejects-foreign-next-token"
GROUP = 'partiql'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An ExecuteStatement NextToken is bound to its issuing statement: it resumes that statement,
    but a different statement on the same table rejects it ValidationException with AWS's message.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqltoken-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'status', 'AttributeType': 'S'},
            {'AttributeName': 'createdAt', 'AttributeType': 'S'},
        ],
        GlobalSecondaryIndexes=[{
            'IndexName': 'status-index',
            'KeySchema': [{'AttributeName': 'status', 'KeyType': 'HASH'}, {'AttributeName': 'createdAt', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    deadline = time.time() + 300
    gsi_status = None
    while time.time() < deadline:
        described = ddb.describe_table(TableName=table)['Table']
        gsi_status = {i['IndexName']: i['IndexStatus'] for i in described.get('GlobalSecondaryIndexes', [])}
        if gsi_status.get('status-index') == 'ACTIVE':
            break
        time.sleep(2)
    assert gsi_status.get('status-index') == 'ACTIVE', f'status-index never became ACTIVE: {gsi_status!r}'

    pk = 'P1'
    ddb.put_item(TableName=table, Item={'pk': {'S': pk}, 'sk': {'S': 's1'}, 'status': {'S': 'active'}, 'createdAt': {'S': '2024-01-01'}})
    ddb.put_item(TableName=table, Item={'pk': {'S': pk}, 'sk': {'S': 's2'}, 'status': {'S': 'active'}, 'createdAt': {'S': '2024-01-02'}})

    base_statement = f"SELECT * FROM \"{table}\" WHERE pk = '{pk}'"
    page1 = ddb.execute_statement(Statement=base_statement, Limit=1)
    token = page1.get('NextToken')
    assert token, f'the first page of a 2-item partition under Limit=1 must carry a NextToken, got {page1!r}'
    assert len(page1['Items']) == 1, f'expected exactly 1 item on page 1, got {page1["Items"]!r}'

    # Positive control: the SAME statement, replayed with its own token, correctly resumes to
    # the second item -- so the mechanism works at all, and the rejection below is specific to
    # issuing the token to a DIFFERENT statement.
    page2 = ddb.execute_statement(Statement=base_statement, Limit=1, NextToken=token)
    assert [i['sk']['S'] for i in page2.get('Items', [])] == ['s2'], (
        f'resuming the issuing statement with its own token must return the second item, got '
        f'{page2.get("Items")!r}'
    )

    # Break exactly one thing: hand the SAME token to a DIFFERENT statement.
    foreign_statement = f"SELECT * FROM \"{table}\".\"status-index\" WHERE status = 'active'"
    try:
        accepted = ddb.execute_statement(Statement=foreign_statement, Limit=1, NextToken=token)
    except ClientError as exc:
        rejected = exc.response
        accepted = None
    else:
        rejected = None

    assert accepted is None, (
        f'a NextToken issued by one statement must be rejected by a different statement, but it '
        f'was accepted and returned {accepted.get("Items") if accepted else None!r}'
    )
    code = rejected['Error'].get('Code')
    message = rejected['Error'].get('Message')
    assert code == ERR_VALIDATION, (
        f'expected {ERR_VALIDATION!r} for a foreign NextToken, got {code!r} ({message!r})'
    )
    expected = 'NextToken does not match request'
    assert message == expected, f'expected message {expected!r}, got {message!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
