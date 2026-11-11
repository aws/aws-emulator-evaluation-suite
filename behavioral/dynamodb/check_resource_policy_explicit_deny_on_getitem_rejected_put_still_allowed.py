"""resource-policy-explicit-deny-on-getitem-rejected-put-still-allowed."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-explicit-deny-on-getitem-rejected-put-still-allowed"
GROUP = 'overly_permissive'
SERVICES = ['dynamodb']
ERR_ACCESS_DENIED = 'AccessDeniedException'
# Phrase AWS uses to attribute a 403 to the resource-based policy rather than another cause.
DENY_ATTRIBUTION = 'explicit deny in a resource-based policy'

# A table resource policy can take several minutes to become effective; the loop fails rather
# than skips at the bound because "never enforced" is the defect being checked.
_PROPAGATION_BUDGET_S = 600


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An explicit Deny on GetItem in a table resource policy rejects GetItem with
    AccessDeniedException while PutItem still succeeds, data is untouched, and deleting it restores
    GetItem; only evaluated, action-scoped enforcement passes.
    """
    ddb = ctx.client('dynamodb')
    sts = ctx.client('sts')
    table = ctx.unique_name('sim2real-behav-rp-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )

    def _drop_table() -> None:
        # DeleteResourcePolicy leaves the table momentarily non-deletable; a single-shot
        # delete_table here raises ResourceInUseException and leaks the table.
        deadline = time.time() + 180
        while time.time() < deadline:
            try:
                ddb.delete_table(TableName=table)
                return
            except ClientError as exc:
                if exc.response['Error']['Code'] != 'ResourceInUseException':
                    raise
                time.sleep(5)
        ddb.delete_table(TableName=table)

    ctx.on_cleanup(_drop_table)
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    arn = ddb.describe_table(TableName=table)['Table']['TableArn']
    ddb.put_item(TableName=table, Item={'pk': {'S': 'first'}})

    caller = sts.get_caller_identity()['Arn']
    policy = {'Version': '2012-10-17', 'Statement': [{
        'Sid': 'DenyGetItemOnly',
        'Effect': 'Deny',
        'Principal': {'AWS': caller},
        'Action': 'dynamodb:GetItem',
        'Resource': arn,
    }]}
    ddb.put_resource_policy(ResourceArn=arn, Policy=json.dumps(policy))

    def _drop_policy() -> None:
        try:
            ddb.delete_resource_policy(ResourceArn=arn)
        except ClientError as exc:
            if exc.response['Error']['Code'] != 'PolicyNotFoundException':
                raise

    ctx.on_cleanup(_drop_policy)

    # A resource-policy change is eventually consistent and exposes no condition that reports
    # "effective", so this is the sanctioned bounded retry at first use of the permission.
    deadline = time.time() + _PROPAGATION_BUDGET_S
    denied = None
    last_ok = None
    while time.time() < deadline:
        try:
            last_ok = ddb.get_item(TableName=table, Key={'pk': {'S': 'first'}},
                                   ConsistentRead=True)
        except ClientError as exc:
            denied = exc.response
            break
        time.sleep(3)

    assert denied is not None, (
        f'the explicit Deny on dynamodb:GetItem was never enforced within '
        f'{_PROPAGATION_BUDGET_S!r}s -- GetItem still returned {last_ok and last_ok.get("Item")!r} '
        f'under policy {json.dumps(policy)}'
    )
    code = denied['Error']['Code']
    message2 = denied['Error']['Message']
    assert code == ERR_ACCESS_DENIED, (
        f'expected {ERR_ACCESS_DENIED!r} from the denied GetItem, got {code!r} '
        f'({denied["Error"].get("Message")!r})'
    )
    assert message2 == f"User: {caller} is not authorized to perform: dynamodb:GetItem on resource: {arn} with an explicit deny in a resource-based policy", (
        f"expected the exact AccessDeniedException message AWS returns, got {message2!r}"
    )
    # Attribute the denial to the resource-based policy specifically: an AccessDeniedException
    # raised for some unrelated reason (identity policy, SCP, a throttle-adjacent misclassification)
    # must not satisfy this leg.
    message = denied['Error'].get('Message', '')
    assert DENY_ATTRIBUTION in message, (
        f'expected the denial message to attribute the block to the resource-based policy '
        f'(substring {DENY_ATTRIBUTION!r}), got {message!r}'
    )

    # Positive control 1: the same principal, the same table, a different action.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'second'}})

    # ... and the Deny disturbed no data: both writes are there, read through an operation the
    # policy does not name.
    scanned = []
    start_key: dict = {}
    while True:
        page = ddb.scan(TableName=table, ConsistentRead=True, **start_key)
        scanned += [i['pk']['S'] for i in page['Items']]
        if 'LastEvaluatedKey' not in page:
            break
        start_key = {'ExclusiveStartKey': page['LastEvaluatedKey']}
    assert sorted(scanned) == ['first', 'second'], (
        f'the denied GetItem or the policy churn disturbed the table contents: {scanned!r}'
    )

    # Positive control 2: remove the one broken thing and the denied call recovers.
    ddb.delete_resource_policy(ResourceArn=arn)
    deadline = time.time() + _PROPAGATION_BUDGET_S
    restored = None
    while time.time() < deadline:
        try:
            restored = ddb.get_item(TableName=table, Key={'pk': {'S': 'first'}},
                                    ConsistentRead=True)
            break
        except ClientError as exc:
            if exc.response['Error']['Code'] != ERR_ACCESS_DENIED:
                raise
            time.sleep(3)
    assert restored is not None and restored.get('Item') == {'pk': {'S': 'first'}}, (
        f'GetItem did not recover after DeleteResourcePolicy within {_PROPAGATION_BUDGET_S!r}s: '
        f'{restored!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
