"""gsi-key-attribute-must-be-scalar."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "gsi-key-attribute-must-be-scalar"
GROUP = 'gsi'
SERVICES = ['dynamodb']


def _error(call, what):
    """The Error dict from a call that MUST be refused."""
    try:
        call()
    except Exception as exc:  # noqa: BLE001 -- the error IS the assertion
        return getattr(exc, 'response', {}).get('Error', {}) or {}
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A secondary index key must be String, Number or Binary. A list or map typed key is refused at
    CreateTable, because an index cannot order a document type."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    err = _error(
        lambda: ddb.create_table(
            TableName=table,
            KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                                  {'AttributeName': 'doc', 'AttributeType': 'L'}],
            GlobalSecondaryIndexes=[{'IndexName': 'idx1',
                                     'KeySchema': [{'AttributeName': 'doc', 'KeyType': 'HASH'}],
                                     'Projection': {'ProjectionType': 'ALL'}}],
            BillingMode='PAY_PER_REQUEST'),
        'a GSI keyed on a list-typed attribute',
    )
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    expected_message = (
        "1 validation error detected: Value 'L' at 'attributeDefinitions.2.member.attributeType' "
        "failed to satisfy constraint: Member must satisfy enum value set: [B, N, S]"
    )
    assert err.get('Message') == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )
    assert table not in ddb.list_tables()['TableNames'], 'the refused table must not exist'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
