"""deploy-cfn-lakeformation-datalakesettings-appends-admin-and-restores-on-cleanup."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-lakeformation-datalakesettings-appends-admin-and-restores-on-cleanup"
GROUP = "deploy"
SERVICES = ["cloudformation", "lakeformation"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_FAILED",
        "UPDATE_ROLLBACK_FAILED",
        "IMPORT_COMPLETE",
        "IMPORT_ROLLBACK_COMPLETE",
        "IMPORT_ROLLBACK_FAILED",
    }
)
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0, ctx=None):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone". With ``ctx``, a wait
    the run budget ended raises TimeoutError.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(
                    f"stack {stack_id} still {status!r}: the run budget ended first; not graded"
                )
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id, timeout_s=_DELETE_BUDGET_S, ctx=None):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + timeout_s
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in (
        "DELETE_IN_PROGRESS",
        "REVIEW_IN_PROGRESS",
    ):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic(), ctx)
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(
        cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, deadline - time.monotonic(), ctx
    )
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [
            i
            for i, e in enumerate(events)
            if e.get("PhysicalResourceId") == stack_id
            and e["ResourceStatus"] == "DELETE_IN_PROGRESS"
        ]
        failed = [
            (e["LogicalResourceId"], e.get("ResourceStatusReason"))
            for e in events[starts[-1] if starts else 0 :]
            if e["ResourceStatus"] == "DELETE_FAILED"
        ]
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
                "ValidationError",
                f"Stack with id {name} does not exist",
            ):
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


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"])
        for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


# ---- Check-specific: the template, then run(). ----


def _template() -> str:
    """An APPEND of the deploying account's root principal as a Lake Formation data lake admin."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Settings": {
                    "Type": "AWS::LakeFormation::DataLakeSettings",
                    "Properties": {
                        "Admins": [
                            {
                                "DataLakePrincipalIdentifier": {
                                    "Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"
                                }
                            }
                        ],
                        "MutationType": "APPEND",
                    },
                },
            },
        }
    )


_OTHER_FIELD_DEFAULTS = {
    "ReadOnlyAdmins": [],
    "CreateDatabaseDefaultPermissions": [],
    "CreateTableDefaultPermissions": [],
    "Parameters": {},
    "TrustedResourceOwners": [],
    "AllowExternalDataFiltering": False,
    "AllowFullTableExternalDataAccess": False,
    "ExternalDataFilteringAllowList": [],
    "AuthorizedSessionTagValueList": [],
}


def _settings_minus_admins(settings: dict) -> dict:
    """Every field but ``DataLakeAdmins``, each defaulted so a once-absent field reads as unset."""
    return {k: settings.get(k, default) for k, default in _OTHER_FIELD_DEFAULTS.items()}


@tags(
    "resource:account-singleton:lakeformation-data-lake-settings",
    "axis:happy-path",
    "cap:c1",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation AWS::LakeFormation::DataLakeSettings with MutationType APPEND adds an admin
    to the account's data lake settings without disturbing any other field, and deleting the stack
    writes back the prior settings plus an empty AuthorizedSessionTagValueList."""
    cfn = ctx.client("cloudformation")
    lf = ctx.client("lakeformation")

    original = lf.get_data_lake_settings()["DataLakeSettings"]
    ctx.on_cleanup(lambda: lf.put_data_lake_settings(DataLakeSettings=original))
    original_admin_ids = {p["DataLakePrincipalIdentifier"] for p in original["DataLakeAdmins"]}
    admin_arn = f"arn:{cfn.meta.partition}:iam::{ctx.account}:root"
    assert admin_arn not in original_admin_ids, f"{admin_arn!r} was already a data lake admin"

    stack_id = create_stack(
        ctx,
        cfn,
        ctx.unique_name("sim2real-behav-cfn-lfset-"),
        _template(),
    )
    status = wait_stack(cfn, stack_id, timeout_s=_budget_s(ctx, 300.0), ctx=ctx)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    settings = lf.get_data_lake_settings()["DataLakeSettings"]
    new_admin_ids = {p["DataLakePrincipalIdentifier"] for p in settings["DataLakeAdmins"]}
    assert new_admin_ids == original_admin_ids | {admin_arn}, (
        f"DataLakeAdmins read back {new_admin_ids!r}, expected {original_admin_ids | {admin_arn}!r}"
    )
    assert _settings_minus_admins(settings) == _settings_minus_admins(original), (
        f"a field besides DataLakeAdmins changed: {_settings_minus_admins(settings)!r} vs "
        f"{_settings_minus_admins(original)!r}"
    )

    delete_stack(cfn, stack_id, timeout_s=_budget_s(ctx, _DELETE_BUDGET_S), ctx=ctx)
    restored = lf.get_data_lake_settings()["DataLakeSettings"]
    # Deleting the resource writes the settings back, and that write adds an empty
    # AuthorizedSessionTagValueList when the original settings did not carry one.
    expected = {"AuthorizedSessionTagValueList": [], **original}
    assert restored == expected, (
        f"after the stack delete the data lake settings read {restored!r}, expected {expected!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
