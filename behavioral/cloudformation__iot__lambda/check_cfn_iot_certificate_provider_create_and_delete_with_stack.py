"""cfn-iot-certificate-provider-create-and-delete-with-stack."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iot-certificate-provider-create-and-delete-with-stack"
GROUP = "deploy"
SERVICES = ["cloudformation", "iot", "lambda"]

# ---- CloudFormation helpers: copy VERBATIM; delete the ones the check never calls. ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_LAMBDA_CODE = (
    "def handler(event, context):\n"
    "    return {'certificate': '-----BEGIN CERTIFICATE-----\\nMIIBNA==\\n-----END CERTIFICATE-----'}\n"
)


def _zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _template(function_name: str, provider_name: str, function_arn: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "InvokePermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "FunctionName": function_name,
                    "Action": "lambda:InvokeFunction",
                    "Principal": "iot.amazonaws.com",
                    "SourceAccount": {"Ref": "AWS::AccountId"},
                },
            },
            "CertProvider": {
                "Type": "AWS::IoT::CertificateProvider",
                "DependsOn": "InvokePermission",
                "Properties": {
                    "CertificateProviderName": provider_name,
                    "LambdaFunctionArn": function_arn,
                    "AccountDefaultForOperations": ["CreateCertificateFromCsr"],
                },
            },
        },
        "Outputs": {
            "ProviderRef": {"Value": {"Ref": "CertProvider"}},
            "ProviderArn": {"Value": {"Fn::GetAtt": ["CertProvider", "Arn"]}},
        },
    })


def _providers(iot) -> list[tuple[str, str]]:
    """(name, ARN) of every certificate provider, all pages (the op has no paginator)."""
    kw, out = {}, []
    while True:
        page = iot.list_certificate_providers(**kw)
        out += [(p["certificateProviderName"], p["certificateProviderArn"])
                for p in page["certificateProviders"]]
        if not page.get("nextToken"):
            return out
        kw["nextToken"] = page["nextToken"]


_LAMBDA_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})


def _lambda_role(ctx, tag_value: str) -> str:
    """The certificate provider function's execution role. The function is never invoked, so
    the role carries no permission beyond the Lambda trust."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-certfn-role-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_LAMBDA_TRUST,
                          Tags=[{"Key": "sim2real", "Value": tag_value}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_function(ctx, lam, name: str, role_arn: str, tag_value: str) -> str:
    """CreateFunction, retrying only the refusal Lambda returns while a new role propagates."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Handler="index.handler", Role=role_arn,
                Code={"ZipFile": _zip_bytes(_LAMBDA_CODE)}, Timeout=10,
                Tags={"sim2real": tag_value},
            )["FunctionArn"]
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"] != "InvalidParameterValueException"
                    or "cannot be assumed" not in err.get("Message", "")
                    or time.monotonic() > deadline):
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    return arn


def _precondition(iot) -> None:
    existing = _providers(iot)
    assert existing == [], (
        f"precondition: no certificate provider may hold the account's CreateCertificateFromCsr "
        f"default before this check runs, found {existing!r}"
    )


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control", "resource:account-singleton:iot-certificate-provider")
def run(ctx) -> None:
    """A CloudFormation IoT CertificateProvider and its Lambda permission read back and revert.

    Ref and GetAtt match the provider IoT lists as the CreateCertificateFromCsr default, Lambda
    holds the account-scoped invoke grant, and the stack delete removes both.
    """
    lam = ctx.client("lambda")
    iot = ctx.client("iot")
    cfn = ctx.client("cloudformation")
    _precondition(iot)
    tag_value = ctx.unique_name("sim2real-xsvc-certprov-")
    function_name = ctx.unique_name("sim2real-xsvc-certfn-")
    function_arn = _create_function(ctx, lam, function_name, _lambda_role(ctx, tag_value),
                                    tag_value)

    provider_name = ctx.unique_name("sim2real-xsvc-certprov-")
    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-xsvc-stk-"),
                            _template(function_name, provider_name, function_arn))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    assert outputs["ProviderRef"] == provider_name, f"Ref {outputs['ProviderRef']!r}"

    # Ref and GetAtt against an independent read: IoT's provider list, every page.
    listed = _providers(iot)
    assert listed == [(provider_name, outputs["ProviderArn"])], f"IoT lists {listed!r}"
    described = iot.describe_certificate_provider(certificateProviderName=provider_name)
    got = (described["certificateProviderName"], described["certificateProviderArn"],
           described["lambdaFunctionArn"], described["accountDefaultForOperations"])
    want = (provider_name, outputs["ProviderArn"], function_arn, ["CreateCertificateFromCsr"])
    assert got == want, f"DescribeCertificateProvider reads {got!r}, expected {want!r}"

    # The Lambda::Permission: one account-scoped IoT invoke grant on the function.
    policy = json.loads(lam.get_policy(FunctionName=function_name)["Policy"])
    statements = [{k: v for k, v in s.items() if k != "Sid"} for s in policy["Statement"]]
    want = [{"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"},
             "Action": "lambda:InvokeFunction", "Resource": function_arn,
             "Condition": {"StringEquals": {"AWS:SourceAccount": ctx.account}}}]
    assert statements == want, f"function policy {statements!r}, expected {want!r}"

    delete_stack(cfn, stack_id)
    expect_error(lambda: iot.describe_certificate_provider(certificateProviderName=provider_name),
                 *("ResourceNotFoundException",
                   f"Certificate provider with name [{provider_name}] not found"))
    assert _providers(iot) == [], "a certificate provider still holds the account default"
    expect_error(lambda: lam.get_policy(FunctionName=function_name),
                 *("ResourceNotFoundException", "The resource you requested does not exist."))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
