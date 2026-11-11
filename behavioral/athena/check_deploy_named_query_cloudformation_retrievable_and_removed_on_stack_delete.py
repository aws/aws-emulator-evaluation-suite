"""deploy-named-query-cloudformation-retrievable-and-removed-on-stack-delete."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deploy-named-query-cloudformation-retrievable-and-removed-on-stack-delete"
GROUP = "deploy"
SERVICES = ["athena"]

_SIM2REAL_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  QueryName:
    Type: String
Resources:
  MyNamedQuery:
    Type: AWS::Athena::NamedQuery
    Properties:
      Name: !Ref QueryName
      Database: "default"
      Description: "sim2real behavioral fidelity check named query"
      QueryString: "SELECT 1 AS answer"
Outputs:
  NamedQueryId:
    Value: !GetAtt MyNamedQuery.NamedQueryId
"""


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A named query deployed via CloudFormation is retrievable with matching SQL
    text, and deleting the stack removes it from ListNamedQueries."""
    query_name = ctx.unique_name("sim2real-behav-nq-")
    stack_name = ctx.unique_name("sim2real-behav-stack-")
    cfn = ctx.client("cloudformation")
    athena = ctx.client("athena")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[{"ParameterKey": "QueryName", "ParameterValue": query_name}],
        Tags=_SIM2REAL_TAGS,
    )
    # safety-net cleanup in case the in-body delete below never runs (early failure)
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    named_query_id = outputs["NamedQueryId"]

    nq = athena.get_named_query(NamedQueryId=named_query_id)["NamedQuery"]
    assert nq["Name"] == query_name, f"expected Name={query_name!r}, got {nq['Name']!r}"
    assert nq["QueryString"] == "SELECT 1 AS answer", (
        f"expected QueryString='SELECT 1 AS answer', got {nq['QueryString']!r}"
    )
    assert nq["Database"] == "default", f"expected Database='default', got {nq['Database']!r}"
    assert nq["Description"] == "sim2real behavioral fidelity check named query", (
        f"expected the CFN-authored Description, got {nq.get('Description')!r}"
    )
    all_ids = _list_all_named_query_ids(ctx)
    assert named_query_id in all_ids, f"{named_query_id} missing from ListNamedQueries {all_ids}"

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    deadline = time.monotonic() + 60.0
    still_present = True
    while time.monotonic() < deadline:
        if named_query_id not in _list_all_named_query_ids(ctx):
            still_present = False
            break
        time.sleep(2)
    assert not still_present, "NamedQueryId still listed after stack deletion"
    err, message = _error(lambda: athena.get_named_query(NamedQueryId=named_query_id))
    assert err == "InvalidRequestException", (
        f"expected GetNamedQuery on the deleted id to fail with InvalidRequestException, got {err!r}"
    )
    expected = f"NamedQuery: {named_query_id} does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to fail, but it SUCCEEDED and returned {result!r}")


def _list_all_named_query_ids(ctx) -> list[str]:
    athena = ctx.client("athena")
    ids: list[str] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = athena.list_named_queries(**kwargs)
        ids.extend(resp.get("NamedQueryIds", []))
        token = resp.get("NextToken")
        if not token:
            break
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
