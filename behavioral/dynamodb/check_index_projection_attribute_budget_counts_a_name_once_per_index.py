"""index-projection-attribute-budget-counts-a-name-once-per-index."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "index-projection-attribute-budget-counts-a-name-once-per-index"
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
    """The 100-attribute projection budget is shared across ALL secondary indexes, and the same
    attribute name projected into two indexes counts TWICE. A target counting distinct names
    accepts a table real AWS refuses."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    # 20 is the per-index NonKeyAttributes ceiling, so each index stays legal on its own; six of
    # them projecting the SAME 20 names spend 120 of the 100-attribute table-wide budget.
    names = [f'a{i}' for i in range(20)]
    n_indexes = 6
    err = _error(
        lambda: ddb.create_table(
            TableName=table,
            KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}] + [
                {'AttributeName': f'g{i}', 'AttributeType': 'S'} for i in range(n_indexes)],
            GlobalSecondaryIndexes=[
                {'IndexName': f'idx{i}', 'KeySchema': [{'AttributeName': f'g{i}', 'KeyType': 'HASH'}],
                 'Projection': {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': names}}
                for i in range(n_indexes)
            ],
            BillingMode='PAY_PER_REQUEST'),
        'six indexes each projecting the same 20 attributes (120 against a 100 budget)',
    )
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    expected = ('One or more parameter values were invalid: Number of projected attributes in all '
                f'indexes exceeds limit of 100, number of projected attributes:{len(names) * n_indexes}')
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"
    assert table not in ddb.list_tables()['TableNames'], 'the refused table must not exist'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
