"""deploy-redshiftserverless-namespace-round-trip-then-delete."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-redshiftserverless-namespace-round-trip-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "redshift-serverless"]

# ---- CloudFormation helpers ----

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

_AWS_TAG = re.compile(r"^aws:")


def _template(namespace_name, admin_username, db_name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Namespace": {
                "Type": "AWS::RedshiftServerless::Namespace",
                "Properties": {
                    "NamespaceName": namespace_name,
                    "AdminUsername": admin_username,
                    "DbName": db_name,
                    "ManageAdminPassword": True,
                },
            },
        },
        "Outputs": {
            "NamespaceRef": {"Value": {"Ref": "Namespace"}},
            "NamespaceArn": {"Value": {"Fn::GetAtt": ["Namespace", "Namespace.NamespaceArn"]}},
            "NamespaceId": {"Value": {"Fn::GetAtt": ["Namespace", "Namespace.NamespaceId"]}},
            "NamespaceAdminUsername": {
                "Value": {"Fn::GetAtt": ["Namespace", "Namespace.AdminUsername"]}
            },
            "NamespaceDbName": {"Value": {"Fn::GetAtt": ["Namespace", "Namespace.DbName"]}},
        },
    })


def _own_namespaces(rss, name):
    rows = paginate(rss, "list_namespaces", "namespaces", maxResults=100)
    return [n for n in rows if n["namespaceName"] == name]



@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Redshift Serverless namespace reads back through Redshift Serverless.

    Ref, GetAtt values, every templated property and the stack tag match, and the delete removes it.
    """
    cf = ctx.client("cloudformation")
    rss = ctx.client("redshift-serverless")
    stack = ctx.unique_name("sim2real-cfnrss-ns-")
    namespace = ctx.unique_name("sim2real-cfnrss-ns-")
    admin_username = "sim2realadmin"
    db_name = "sim2realdb"

    stack_id = create_stack(ctx, cf, stack, _template(namespace, admin_username, db_name))
    status = wait_stack(cf, stack_id, timeout_s=300.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    partition = stack_id.split(":")[1]

    # Ref against an independent read (ListNamespaces by the declared name), never a read by Ref.
    listed = _own_namespaces(rss, namespace)
    assert len(listed) == 1, f"ListNamespaces found {listed!r} for namespace {namespace!r}"
    found = listed[0]
    assert found["namespaceName"] == out["NamespaceRef"], (
        f"ListNamespaces namespaceName {found['namespaceName']!r} != Ref {out['NamespaceRef']!r}"
    )

    arn = (f"arn:{partition}:redshift-serverless:{ctx.region}:{ctx.account}:"
           f"namespace/{found['namespaceId']}")
    # Read-only GetAtt values == the service's own read; echoed inputs == the template input too.
    assert out["NamespaceArn"] == found["namespaceArn"] == arn, (
        f"GetAtt Arn {out['NamespaceArn']!r}, ListNamespaces arn {found['namespaceArn']!r}, "
        f"expected {arn!r}"
    )
    assert out["NamespaceId"] == found["namespaceId"], (
        f"GetAtt NamespaceId {out['NamespaceId']!r} != ListNamespaces {found['namespaceId']!r}"
    )
    assert (out["NamespaceAdminUsername"], found["adminUsername"]) == (admin_username,) * 2, (
        f"GetAtt AdminUsername {out['NamespaceAdminUsername']!r}, "
        f"ListNamespaces {found['adminUsername']!r}, expected {admin_username!r}"
    )
    assert (out["NamespaceDbName"], found["dbName"]) == (db_name,) * 2, (
        f"GetAtt DbName {out['NamespaceDbName']!r}, ListNamespaces {found['dbName']!r}, "
        f"expected {db_name!r}"
    )

    # Independently, GetNamespace by the declared name carries the same values plus the propagated
    # stack tag (dropping CloudFormation's own aws: system tags, which are not what the stack set).
    detail = rss.get_namespace(namespaceName=namespace)["namespace"]
    assert detail["namespaceId"] == found["namespaceId"], (
        f"GetNamespace id {detail['namespaceId']!r} != ListNamespaces id {found['namespaceId']!r}"
    )
    # ManageAdminPassword: Redshift Serverless holds the admin password in a Secrets Manager
    # secret of this account and region, and reports that secret's ARN.
    secret_arn = detail.get("adminPasswordSecretArn", "")
    secret_re = rf"arn:{partition}:secretsmanager:{ctx.region}:{ctx.account}:secret:\S+"
    assert re.fullmatch(secret_re, secret_arn), (
        f"ManageAdminPassword: adminPasswordSecretArn {secret_arn!r} is not a secret ARN"
    )
    tag_list = rss.list_tags_for_resource(resourceArn=detail["namespaceArn"]).get("tags", [])
    own_tags = {t["key"]: t["value"] for t in tag_list if not _AWS_TAG.match(t["key"])}
    assert own_tags == {"sim2real": stack}, f"propagated tags {own_tags!r}, expected {stack!r}"

    delete_stack(cf, stack_id)
    gone = ("ResourceNotFoundException", f"Serverless namespace {namespace} not found.")
    expect_error(lambda: rss.get_namespace(namespaceName=namespace), *gone)
    gone = _own_namespaces(rss, namespace)
    assert gone == [], f"ListNamespaces still shows the deleted namespace: {gone!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
