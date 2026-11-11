"""data-api-statement-id-and-target-validation-rejected."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-api-statement-id-and-target-validation-rejected"
GROUP = 'overly-permissive'
SERVICES = ['redshift']



_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)

DB_NAME = "devdb"
MASTER_USERNAME = "adminuser"


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _err(fn):
    """Call *fn*; return the (code, message) of the AWS error it raises, or ("OK", None)."""
    try:
        _retrying(fn)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    return "OK", None


_ONE_TARGET_MESSAGE = (
    "There should be only one of the following: ClusterIdentifier, WorkgroupName, Glue resource, SessionId"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """The Data API returns ValidationException for malformed ids, targets and tokens, and
    ResourceNotFoundException for well-formed absent statement ids; rejected submits create nothing.
    """
    rsd = ctx.client("redshift-data")

    # The Data API's statement Id is a uuid.
    absent_id = str(uuid.uuid4())

    # 1. Malformed id: fails the input contract, so it is a validation error and NOT a
    #    not-found. (botocore does not enforce string patterns client-side, so this reaches
    #    the service.)
    malformed, message = _err(lambda: rsd.describe_statement(Id="not-a-statement-id"))
    assert malformed == "ValidationException", (
        f"a malformed statement Id must be a ValidationException, got {malformed}"
    )
    assert message == (
        "1 validation error detected: Value 'not-a-statement-id' at 'id' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [a-z0-9]{8}(-[a-z0-9]{4}){3}-[a-z0-9]{12}(:\\d{0,2})?"
    ), message

    # 2. Well-formed but absent: not-found, consistently across all three id-taking ops.
    for op_name, call in (
        ("describe_statement", lambda: rsd.describe_statement(Id=absent_id)),
        ("get_statement_result", lambda: rsd.get_statement_result(Id=absent_id)),
        ("cancel_statement", lambda: rsd.cancel_statement(Id=absent_id)),
    ):
        code, message = _err(call)
        assert code == "ResourceNotFoundException", (
            f"{op_name} on a well-formed absent statement id must be "
            f"ResourceNotFoundException, got {code}"
        )
        assert message == "Query does not exist.", f"{op_name}: {message!r}"

    # The two classes must not be the same code — collapsing them is the defect.
    assert malformed != "ResourceNotFoundException", (
        "malformed input and absent-resource must be distinct error classes"
    )

    # 3. Missing target: ExecuteStatement requires exactly one of ClusterIdentifier or
    #    WorkgroupName. Supplying neither is a contract violation the service must reject.
    statement_name = ctx.unique_name("sim2real-behav-rs-rejected-")
    no_target, message = _err(
        lambda: rsd.execute_statement(
            Database=DB_NAME,
            DbUser=MASTER_USERNAME,
            Sql="SELECT 1",
            StatementName=statement_name,
        )
    )
    assert no_target == "ValidationException", (
        "ExecuteStatement with neither ClusterIdentifier nor WorkgroupName must be a "
        f"ValidationException, got {no_target}"
    )
    assert message == _ONE_TARGET_MESSAGE, message

    # 4. Both targets, naming a cluster that does not exist: the Data API resolves the cluster
    #    first and rejects the call with a ValidationException naming the missing endpoint.
    both_targets, message = _err(
        lambda: rsd.execute_statement(
            ClusterIdentifier="sim2real-behav-rs-absent-cluster",
            WorkgroupName="sim2real-behav-rs-absent-workgroup",
            Database=DB_NAME,
            Sql="SELECT 1",
            StatementName=statement_name,
        )
    )
    assert both_targets == "ValidationException", (
        "ExecuteStatement naming BOTH ClusterIdentifier and WorkgroupName must be a "
        f"ValidationException, got {both_targets}"
    )
    assert message == "Redshift endpoint doesn't exist in this region.", message

    # 5. Batch form must reject the same way, not accept-then-fail asynchronously.
    batch_no_target, message = _err(
        lambda: rsd.batch_execute_statement(
            Database=DB_NAME,
            DbUser=MASTER_USERNAME,
            Sqls=["SELECT 1"],
            StatementName=statement_name,
        )
    )
    assert batch_no_target == "ValidationException", (
        "BatchExecuteStatement with no target must be a ValidationException, got "
        f"{batch_no_target}"
    )
    assert message == _ONE_TARGET_MESSAGE, message

    # Effect absent: none of the rejected submissions registered a statement.
    listed = _retrying(lambda: rsd.list_statements(StatementName=statement_name, MaxResults=20))
    assert listed["Statements"] == [], (
        "a rejected ExecuteStatement/BatchExecuteStatement must not create a statement record, "
        f"got {listed['Statements']!r}"
    )

    # 6. Malformed pagination token is a validation error, not a silent first page.
    bad_token, message = _err(lambda: rsd.list_statements(NextToken="not-a-real-token", MaxResults=1))
    assert bad_token == "ValidationException", (
        f"a malformed NextToken must be a ValidationException, got {bad_token}"
    )
    assert message == "Invalid token value", message

    # Control: a well-formed list succeeds.
    control = _retrying(lambda: rsd.list_statements(MaxResults=1))
    assert isinstance(control["Statements"], list), control
    assert "ResponseMetadata" in control, control


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
