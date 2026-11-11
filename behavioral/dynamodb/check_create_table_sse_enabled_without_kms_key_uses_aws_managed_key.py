"""create-table-sse-enabled-without-kms-key-uses-aws-managed-key."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-table-sse-enabled-without-kms-key-uses-aws-managed-key"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']


def _safe_delete_table(ddb, table_name):
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ResourceNotFoundException':
            raise


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTable with SSESpecification Enabled and no KMS key id reports an SSEDescription
    for the AWS owned/managed key -- ENABLED, type KMS, and a KMS key ARN resolving to a
    customer-account KMS key AWS itself manages, never a customer-supplied one.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_SSESpecification.html
    """
    ddb = ctx.client('dynamodb')
    kms = ctx.client('kms')

    table_name = ctx.unique_name('sim2real-behav-ddb-sse-default-')
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table_name))
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        SSESpecification={'Enabled': True},
    )
    ddb.get_waiter('table_exists').wait(TableName=table_name, WaiterConfig={'Delay': 2, 'MaxAttempts': 60})

    sse = ddb.describe_table(TableName=table_name)['Table']['SSEDescription']
    assert sse['Status'] == 'ENABLED', f'expected SSEDescription.Status ENABLED, got {sse["Status"]!r}'
    assert sse['SSEType'] == 'KMS', f'expected SSEDescription.SSEType KMS, got {sse["SSEType"]!r}'
    key_arn = sse['KMSMasterKeyArn']
    assert key_arn.startswith(f'arn:aws:kms:{ctx.region}:{ctx.account}:key/'), (
        f'expected a key ARN in this account and region, got {key_arn!r}'
    )

    key_id = key_arn.rsplit('/', 1)[-1]
    meta = kms.describe_key(KeyId=key_id)['KeyMetadata']
    assert meta['KeyManager'] == 'AWS', (
        f'the key behind an unspecified KMSMasterKeyId must be AWS-managed, got KeyManager {meta["KeyManager"]!r}'
    )
    aliases = {a['AliasName'] for a in kms.list_aliases(KeyId=key_id)['Aliases']}
    assert 'alias/aws/dynamodb' in aliases, (
        f'expected the resolved key to carry alias/aws/dynamodb, got aliases {sorted(aliases)!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
