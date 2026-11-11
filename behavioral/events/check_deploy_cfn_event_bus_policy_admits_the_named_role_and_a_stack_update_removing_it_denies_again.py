"""deploy-cfn-event-bus-policy-admits-the-named-role-and-a-stack-update-removing-it-denies-again."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-event-bus-policy-admits-the-named-role-and-a-stack-update-removing-it-denies-again"
GROUP = "deploy"
SERVICES = ["events"]

_SESSION = "sim2real-behav"


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack-deployed EventBusPolicy admits PutEvents from a role with no identity policy and
    refuses an unnamed role; a stack update removing only the policy refuses the named role again.
    """
    cfn = ctx.client("cloudformation")
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    named_name, named_arn = _bare_role(ctx)
    other_name, other_arn = _bare_role(ctx)
    named = ctx.client("events", creds=_assume(ctx, named_arn))
    other = ctx.client("events", creds=_assume(ctx, other_arn))

    stack = ctx.unique_name("sim2real-evb-polstk-")
    names = {"bus": ctx.unique_name("sim2real-evb-cfnpol-"), "rule": ctx.unique_name("sim2real-evb-cfnpolrule-"),
             "source": ctx.unique_name("sim2real.cfnpol."), "role": named_arn}
    cfn.create_stack(StackName=stack, TemplateBody=_template(names, with_policy=True),
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))
    status = _wait_stack(cfn, stack, "CREATE_COMPLETE", timeout_s=300.0)
    assert status == "CREATE_COMPLETE", f"stack create ended {status!r}: {_failure_reasons(cfn, stack)!r}"
    out = _outputs(cfn, stack)
    bus_arn = out["BusArn"]

    statements = json.loads(events.describe_event_bus(Name=names["bus"])["Policy"])["Statement"]
    assert [s.get("Sid") for s in statements] == ["AllowNamedRole"], (
        f"the deployed bus policy has statements {[s.get('Sid') for s in statements]!r}"
    )

    marker = ctx.unique_name("m-")
    resp = _until(lambda: named.put_events(Entries=[_entry(names, marker)]), admitted=True, timeout_s=90.0)
    assert resp["FailedEntryCount"] == 0, f"the admitted PutEvents reported {resp['Entries']!r}"
    got = _await_marker(sqs, out["QueueUrl"], marker, timeout_s=90.0)
    assert got["source"] == names["source"], f"delivered event source was {got['source']!r}"

    code, message = _error(lambda: other.put_events(Entries=[_entry(names, ctx.unique_name("o-"))]))
    assert code == "AccessDeniedException", f"PutEvents by the role the statement does not name gave {code!r}"
    assert message == _denied(ctx, other_name, bus_arn), f"refusal message was {message!r}"

    cfn.update_stack(StackName=stack, TemplateBody=_template(names, with_policy=False))
    status = _wait_stack(cfn, stack, "UPDATE_COMPLETE", timeout_s=300.0)
    assert status == "UPDATE_COMPLETE", f"stack update ended {status!r}: {_failure_reasons(cfn, stack)!r}"
    after = _outputs(cfn, stack)
    assert after["BusArn"] == bus_arn and after["QueueUrl"] == out["QueueUrl"], (
        "the update replaced the bus or the queue instead of removing only the policy"
    )
    assert "Policy" not in events.describe_event_bus(Name=names["bus"]), "the bus still has a policy"

    code, message = _until(lambda: named.put_events(Entries=[_entry(names, ctx.unique_name("r-"))]),
                           admitted=False, timeout_s=90.0)
    assert code == "AccessDeniedException", f"PutEvents after the policy was removed gave {code!r}"
    assert message == _denied(ctx, named_name, bus_arn), f"refusal message after removal was {message!r}"


def _template(names: dict, *, with_policy: bool) -> str:
    resources = {
        "Bus": {"Type": "AWS::Events::EventBus", "Properties": {"Name": names["bus"]}},
        "Queue": {"Type": "AWS::SQS::Queue", "Properties": {}},
        "Rule": {"Type": "AWS::Events::Rule", "Properties": {
            "Name": names["rule"], "EventBusName": {"Ref": "Bus"},
            "EventPattern": {"source": [names["source"]]}, "State": "ENABLED",
            "Targets": [{"Id": "queue", "Arn": {"Fn::GetAtt": ["Queue", "Arn"]}}]}},
        "QueuePolicy": {"Type": "AWS::SQS::QueuePolicy", "Properties": {
            "Queues": [{"Ref": "Queue"}],
            "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage", "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                "Condition": {"ArnEquals": {"aws:SourceArn": {"Fn::GetAtt": ["Rule", "Arn"]}}}}]}}},
    }
    if with_policy:
        resources["BusPolicy"] = {"Type": "AWS::Events::EventBusPolicy", "Properties": {
            "EventBusName": {"Ref": "Bus"}, "StatementId": "AllowNamedRole",
            "Statement": {"Effect": "Allow", "Principal": {"AWS": names["role"]},
                          "Action": "events:PutEvents", "Resource": {"Fn::GetAtt": ["Bus", "Arn"]}}}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": {"QueueUrl": {"Value": {"Ref": "Queue"}}, "BusArn": {"Value": {"Fn::GetAtt": ["Bus", "Arn"]}}},
    })


def _denied(ctx, role_name: str, bus_arn: str) -> str:
    return (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{_SESSION} is not authorized "
        f"to perform: events:PutEvents on resource: {bus_arn} because no identity-based policy "
        f"allows the events:PutEvents action"
    )


def _entry(names: dict, marker: str) -> dict:
    return {"EventBusName": names["bus"], "Source": names["source"], "DetailType": "sim2real-cfn-policy",
            "Detail": json.dumps({"marker": marker})}


def _error(fn, timeout_s: float = 60.0):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails.

    A just-minted session token can be refused as unrecognized for a few seconds; that is
    retried, never returned.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "UnrecognizedClientException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            return err.get("Code"), err.get("Message")
        raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _until(fn, *, admitted: bool, timeout_s: float):
    """Poll a PutEvents across bus-policy propagation until it is admitted (returns the response)
    or refused (returns the error's code and message)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
            if admitted:
                return last
        except ClientError as exc:
            err = exc.response.get("Error", {})
            last = err
            if not admitted and err.get("Code") == "AccessDeniedException":
                return err.get("Code"), err.get("Message")
            if err.get("Code") not in ("AccessDeniedException", "UnrecognizedClientException"):
                raise
        time.sleep(3)
    raise AssertionError(f"PutEvents never became {'admitted' if admitted else 'refused'}: last {last!r}")


def _bare_role(ctx) -> tuple[str, str]:
    """A role the account may assume, with no identity policy of any kind."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-evb-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return name, arn


def _assume(ctx, role_arn: str, timeout_s: float = 60.0) -> dict:
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            c = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION)["Credentials"]
            return {"aws_access_key_id": c["AccessKeyId"], "aws_secret_access_key": c["SecretAccessKey"],
                    "aws_session_token": c["SessionToken"]}
        except ClientError as exc:
            last = exc
            time.sleep(3)
    raise AssertionError(f"could not assume the check's role in {timeout_s}s: {last}")


def _outputs(cfn, stack: str) -> dict:
    return {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName=stack)["Stacks"][0]["Outputs"]}


def _wait_stack(cfn, stack: str, goal: str, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        if status == goal or status.endswith("_FAILED") or status.endswith("ROLLBACK_COMPLETE"):
            return status
        time.sleep(5)
    raise AssertionError(f"stack did not settle within {timeout_s}s (last {status!r})")


def _failure_reasons(cfn, stack: str) -> list:
    evs = cfn.describe_stack_events(StackName=stack)["StackEvents"]
    return [e.get("ResourceStatusReason") for e in evs if e["ResourceStatus"].endswith("FAILED")][:5]


def _delete_stack(cfn, stack: str, timeout_s: float = 240.0) -> None:
    cfn.delete_stack(StackName=stack)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ValidationError":
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack teardown failed: {_failure_reasons(cfn, stack)!r}")
        time.sleep(5)
    raise AssertionError(f"stack teardown did not finish within {timeout_s}s")


def _await_marker(sqs, url: str, marker: str, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                     WaitTimeSeconds=5).get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
            body = json.loads(m["Body"])
            if body.get("detail", {}).get("marker") == marker:
                return body
    raise AssertionError(f"event {marker!r} was never delivered to the deployed queue in {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
