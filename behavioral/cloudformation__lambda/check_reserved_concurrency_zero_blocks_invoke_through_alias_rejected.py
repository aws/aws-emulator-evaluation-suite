"""reserved-concurrency-zero-blocks-invoke-through-alias-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reserved-concurrency-zero-blocks-invoke-through-alias-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

_STACK_DEADLINE_S = 300.0
_ALIAS = "live"

#: A stub handler: it is never reached by the throttled alias, so its body is irrelevant.
_SRC = "def handler(event, context):\n    return {'ok': True}\n"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A Function whose CFN-declared ReservedConcurrentExecutions is 0 refuses Invoke through its
    alias without running the handler, while a function with no reserved concurrency still invokes.
    """
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    stack = _Stack(ctx, ctx.unique_name("sim2real-rc0-"))
    throttled_fn = f"{stack.name}-throttled"
    control_fn = f"{stack.name}-control"
    # Registered before the create, so LIFO reaps the log groups after the stack delete.
    for fn in (throttled_fn, control_fn):
        ctx.on_cleanup(lambda fn=fn: _reap_log_group(logs, f"/aws/lambda/{fn}"))
    assert stack.create(_template(stack.name)) == "CREATE_COMPLETE", (
        f"the stack did not create: {stack.status()!r}")

    concurrency = lam.get_function(FunctionName=throttled_fn).get("Concurrency")
    assert concurrency == {"ReservedConcurrentExecutions": 0}, (
        f"GetFunction on the CFN-declared throttled function reports Concurrency {concurrency!r}"
    )
    reserved = lam.get_function_concurrency(FunctionName=throttled_fn)
    assert reserved.get("ReservedConcurrentExecutions") == 0, (
        f"GetFunctionConcurrency on the CFN-declared throttled function reported "
        f"{reserved.get('ReservedConcurrentExecutions')!r}, expected 0"
    )

    # Positive control: the sibling alias, with no reserved concurrency, still invokes.
    control_resp = lam.invoke(FunctionName=control_fn, Qualifier=_ALIAS,
                              InvocationType="RequestResponse", Payload=json.dumps({}).encode())
    assert "FunctionError" not in control_resp, (
        f"the control function errored: {control_resp.get('FunctionError')!r}"
    )
    control_body = json.loads(control_resp["Payload"].read())
    assert control_body == {"ok": True}, f"control invoke returned {control_body!r}"

    code, message = _error(
        lambda: lam.invoke(FunctionName=throttled_fn, Qualifier=_ALIAS,
                          InvocationType="RequestResponse", Payload=json.dumps({}).encode())
    )
    assert code == "TooManyRequestsException", (
        f"invoking the alias of a function reserved at 0 concurrency raised {code!r}, expected "
        f"TooManyRequestsException"
    )
    assert message == "Rate Exceeded.", (
        f"the TooManyRequestsException message was {message!r}, expected the literal "
        f"'Rate Exceeded.'"
    )

    # The refusal never ran the handler: the throttled function never created its log group.
    throttled_group = f"/aws/lambda/{throttled_fn}"
    groups = logs.describe_log_groups(logGroupNamePrefix=throttled_group)["logGroups"]
    assert [g["logGroupName"] for g in groups if g["logGroupName"] == throttled_group] == [], (
        f"the throttled function wrote logs, so its handler ran: {groups!r}"
    )

    role_name = stack.cfn.describe_stack_resource(StackName=stack.name, LogicalResourceId="Role")[
        "StackResourceDetail"]["PhysicalResourceId"]
    assert stack.delete() == 0, f"stack {stack.name} did not reach DELETE_COMPLETE"
    for fn in (throttled_fn, control_fn):
        got = _error(lambda fn=fn: lam.get_function(FunctionName=fn))
        want = ("ResourceNotFoundException",
                f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}")
        assert got == want, f"GetFunction on {fn} after the stack delete: {got!r}"
    got = _error(lambda: ctx.client("iam").get_role(RoleName=role_name))
    assert got == ("NoSuchEntity", f"The role with name {role_name} cannot be found."), (
        f"GetRole on the stack's role after the stack delete: {got!r}"
    )


def _template(tok: str) -> str:
    """One role, two functions: `throttled` (ReservedConcurrentExecutions=0) and `control`
    (none), each published as a Version with a `live` Alias.
    """
    res: dict = {"Role": {"Type": "AWS::IAM::Role", "Properties": {
        "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"}]},
        "ManagedPolicyArns": [
            "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]}}}
    for name, reserved in (("throttled", 0), ("control", None)):
        props: dict = {
            "FunctionName": f"{tok}-{name}", "Runtime": "python3.12", "Handler": "index.handler",
            "Role": {"Fn::GetAtt": ["Role", "Arn"]}, "Code": {"ZipFile": _SRC},
        }
        if reserved is not None:
            props["ReservedConcurrentExecutions"] = reserved
        res[f"Fn{name.capitalize()}"] = {"Type": "AWS::Lambda::Function", "Properties": props}
        res[f"Fn{name.capitalize()}Version"] = {
            "Type": "AWS::Lambda::Version",
            "Properties": {"FunctionName": {"Ref": f"Fn{name.capitalize()}"}}}
        res[f"Fn{name.capitalize()}Alias"] = {
            "Type": "AWS::Lambda::Alias",
            "Properties": {
                "FunctionName": {"Ref": f"Fn{name.capitalize()}"}, "Name": _ALIAS,
                "FunctionVersion": {"Fn::GetAtt": [f"Fn{name.capitalize()}Version", "Version"]},
            }}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": res})


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 2.0,
                    budget_s: float = 50.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(f"log group {name} still present after {budget_s}s of deletes")
            time.sleep(interval_s)


def _poll(probe, predicate, *, timeout_s=120.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s. Last: {last!r}")
        time.sleep(interval_s)


def _error(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as exc:
        return str(exc.response["Error"]["Code"]), str(exc.response["Error"].get("Message", ""))
    raise AssertionError("the call succeeded; it must be rejected")


class _Stack:
    """One stack under a unique name, its delete registered BEFORE the create."""

    def __init__(self, ctx, tok: str) -> None:
        self.ctx, self.name, self.cfn = ctx, tok, ctx.client("cloudformation")
        self._deleted: int | None = None

    def create(self, body: str) -> str:
        self.ctx.on_cleanup(self._delete_net)
        self.cfn.create_stack(StackName=self.name, TemplateBody=body,
                              Capabilities=["CAPABILITY_IAM"])
        return self.wait()

    def status(self) -> str:
        try:
            return self.cfn.describe_stacks(StackName=self.name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" in str(exc):
                return "GONE"
            raise

    def wait(self) -> str:
        return _poll(self.status, lambda s: not s.endswith("_IN_PROGRESS"),
                     timeout_s=_STACK_DEADLINE_S, interval_s=2.0,
                     description=f"stack {self.name} reached a terminal status")

    def delete(self) -> int:
        if self._deleted is not None:
            return self._deleted
        if self.status() == "GONE":
            self._deleted = 0
            return 0
        self.cfn.delete_stack(StackName=self.name)
        final = _poll(self.status, lambda s: s in ("GONE", "DELETE_FAILED"),
                      timeout_s=_STACK_DEADLINE_S, interval_s=2.0,
                      description=f"stack {self.name} deleted")
        self._deleted = 0 if final == "GONE" else 1
        return self._deleted

    def _delete_net(self) -> None:
        if self.status().endswith("_IN_PROGRESS"):
            self.wait()
        if self.delete() != 0:
            raise AssertionError(f"stack {self.name} did not reach DELETE_COMPLETE")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
