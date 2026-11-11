"""deploy-domain-cfn-index-operations-behave."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags


CHECK = "deploy-domain-cfn-index-operations-behave"
GROUP = "deploy"
SERVICES = ["opensearch"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  DomainNameParam:
    Type: String
Resources:
  Domain:
    Type: AWS::OpenSearchService::Domain
    Properties:
      DomainName: !Ref DomainNameParam
      ClusterConfig:
        InstanceType: t3.small.search
        InstanceCount: 1
        DedicatedMasterEnabled: false
        ZoneAwarenessEnabled: false
      EBSOptions:
        EBSEnabled: true
        VolumeType: gp3
        VolumeSize: 10
      AccessPolicies:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Sub 'arn:${AWS::Partition}:iam::${AWS::AccountId}:root'
            Action: 'es:*'
            Resource: !Sub 'arn:${AWS::Partition}:es:${AWS::Region}:${AWS::AccountId}:domain/${DomainNameParam}/*'
Outputs:
  DomainArn:
    Value: !GetAtt Domain.Arn
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed domain accepts full index CRUD after stack CREATE_COMPLETE."""
    domain_name = _short_name(ctx.unique_name("aosdxc"), 28)
    stack_name = ctx.unique_name("sim2real-behav-osidx-")
    _deploy_cfn_stack(ctx, stack_name, _TEMPLATE, {"DomainNameParam": domain_name})

    opensearch = ctx.client("opensearch")
    _wait_domain_active(ctx, opensearch, domain_name)

    index_name = "sim2real-idx-behav"

    create_resp = opensearch.create_index(
        DomainName=domain_name,
        IndexName=index_name,
        IndexSchema={"mappings": {"properties": {"title": {"type": "text"}}}},
    )
    assert create_resp["Status"] == "CREATED", f"expected CREATED, got {create_resp['Status']}"

    get_resp = opensearch.get_index(DomainName=domain_name, IndexName=index_name)
    assert _deep_contains(
        get_resp["IndexSchema"], lambda o: isinstance(o, dict) and o.get("type") == "text"
    ), "created mapping field not visible via GetIndex"

    update_resp = opensearch.update_index(
        DomainName=domain_name,
        IndexName=index_name,
        IndexSchema={"mappings": {"properties": {"body": {"type": "keyword"}}}},
    )
    assert update_resp["Status"] == "UPDATED", f"expected UPDATED, got {update_resp['Status']}"

    get_resp2 = opensearch.get_index(DomainName=domain_name, IndexName=index_name)
    assert _deep_contains(
        get_resp2["IndexSchema"], lambda o: isinstance(o, dict) and o.get("type") == "keyword"
    ), "updated mapping field not visible via GetIndex"
    assert _deep_contains(
        get_resp2["IndexSchema"], lambda o: isinstance(o, dict) and o.get("type") == "text"
    ), "original mapping field disappeared after update"

    delete_resp = opensearch.delete_index(DomainName=domain_name, IndexName=index_name)
    assert delete_resp["Status"] == "DELETED", f"expected DELETED, got {delete_resp['Status']}"

    code, message = _error_code(lambda: opensearch.get_index(DomainName=domain_name, IndexName=index_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException from GetIndex on a deleted index, got {code}"
    gone = f"Resource index {index_name} does not exist"
    assert message == gone, f"GetIndex not-found message {message!r}, expected {gone!r}"

    update_code, update_message = _error_code(
        lambda: opensearch.update_index(
            DomainName=domain_name,
            IndexName=index_name,
            IndexSchema={"mappings": {"properties": {"z": {"type": "keyword"}}}},
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected UpdateIndex on a deleted index to also fail not-found, got {update_code}"
    )
    assert update_message == gone, f"UpdateIndex not-found message {update_message!r}, expected {gone!r}"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _short_name(raw: str, max_len: int, min_len: int = 3) -> str:
    name = "".join(c for c in raw.lower() if c.isalnum() or c == "-")
    if len(name) > max_len:
        name = name[:max_len]
    name = name.rstrip("-")
    if not name or not name[0].isalpha():
        name = "a" + name[1:]
    while len(name) < min_len:
        name += "0"
    return name


def _error_code(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _deep_contains(obj: Any, predicate) -> bool:
    if predicate(obj):
        return True
    if isinstance(obj, dict):
        return any(_deep_contains(v, predicate) for v in obj.values())
    if isinstance(obj, list):
        return any(_deep_contains(v, predicate) for v in obj)
    return False


def _deploy_cfn_stack(ctx, stack_name: str, template_body: str, parameters: dict[str, str]) -> dict[str, str]:
    cfn = ctx.client("cloudformation")

    def _cleanup() -> None:
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 870})

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Capabilities=["CAPABILITY_IAM"],
        OnFailure="DELETE",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(_cleanup)
    waiter = cfn.get_waiter("stack_create_complete")
    try:
        waiter.wait(
            StackName=stack_name,
            WaiterConfig={"Delay": 2, "MaxAttempts": int(_budget_s(ctx, 2400.0) / 2) + 1},
        )
    except WaiterError as err:
        if _budget_spent(ctx):
            raise TimeoutError(f"stack {stack_name} to create: the run budget ended first; not graded") from err
        raise
    resp = cfn.describe_stacks(StackName=stack_name)
    return {o["OutputKey"]: o["OutputValue"] for o in resp["Stacks"][0].get("Outputs", [])}


def _wait_domain_active(ctx, opensearch, domain_name: str, timeout_s: float = 1800.0) -> dict[str, Any]:
    def _delete() -> None:
        try:
            opensearch.delete_domain(DomainName=domain_name)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_delete)
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = opensearch.describe_domain(DomainName=domain_name)["DomainStatus"]
        if status.get("Created") and not status.get("Processing") and status.get("Endpoint"):
            return status
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} to become active: the run budget ended first; not graded")
    raise AssertionError(f"domain {domain_name} never became active within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
