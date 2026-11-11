"""import-existing-resources-adopts-named-parameter."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-existing-resources-adopts-named-parameter"
GROUP = "change-set-import"
SERVICES = ["cloudformation"]

STACK_TIMEOUT_S = 180.0


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:data-plane", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """With ImportExistingResources a change set imports an existing SSM parameter by name, the stack
    owns it without changing its value and an update rewrites it; a plain CreateStack declaring the
    same name ends ROLLBACK_COMPLETE and leaves it untouched."""
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    name = "/" + ctx.unique_name("sim2real-cfn-import-")

    ssm.put_parameter(Name=name, Type="String", Value="preexisting")
    ctx.on_cleanup(lambda: _delete_param(ssm, name))

    def template(value: str) -> str:
        return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"P": {
            "Type": "AWS::SSM::Parameter", "DeletionPolicy": "Retain",
            "UpdateReplacePolicy": "Retain",
            "Properties": {"Name": name, "Type": "String", "Value": value}}}})

    # --- Control: without ImportExistingResources the same name collides and nothing changes ---
    plain = cfn.create_stack(StackName=ctx.unique_name("sim2real-cfn-import-plain-"),
                             TemplateBody=template("clobbered"),
                             Tags=[{"Key": "sim2real", "Value": CHECK}])["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=plain))
    plain_status = _wait(cfn, plain, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"})
    assert plain_status == "ROLLBACK_COMPLETE", (
        f"CreateStack declaring an existing parameter name: expected ROLLBACK_COMPLETE, got "
        f"{plain_status!r}"
    )
    assert _param(ssm, name) == "preexisting", (
        f"the failed plain create must not touch the existing parameter; read {_param(ssm, name)!r}"
    )

    # --- The import change set ----------------------------------------------------------------
    stack_name = ctx.unique_name("sim2real-cfn-import-")
    cs = cfn.create_change_set(StackName=stack_name, ChangeSetName="sim2real-import",
                               ChangeSetType="CREATE", TemplateBody=template("preexisting"),
                               ImportExistingResources=True,
                               Tags=[{"Key": "sim2real", "Value": CHECK}])
    stack_id = cs["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_id))
    desc = _wait_change_set(cfn, cs["Id"])
    assert desc["Status"] == "CREATE_COMPLETE", f"change set: expected CREATE_COMPLETE, got {desc!r}"
    changes = [(c["ResourceChange"]["Action"], c["ResourceChange"]["LogicalResourceId"],
                c["ResourceChange"].get("PhysicalResourceId")) for c in desc["Changes"]]
    assert changes == [("Import", "P", name)], (
        f"an existing named parameter must be classified Import with its physical id; got {changes!r}"
    )

    cfn.execute_change_set(ChangeSetName=cs["Id"])
    done = _wait(cfn, stack_id, {"CREATE_COMPLETE", "IMPORT_COMPLETE", "ROLLBACK_COMPLETE",
                                 "IMPORT_ROLLBACK_COMPLETE", "ROLLBACK_FAILED"})
    assert done == "CREATE_COMPLETE", f"executed import change set: got stack status {done!r}"
    phys = cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId="P")[
        "StackResourceDetail"]["PhysicalResourceId"]
    assert phys == name, f"the stack must own the existing parameter {name!r}, got {phys!r}"
    assert _param(ssm, name) == "preexisting", "the import itself must not rewrite the value"

    # --- The stack now MANAGES it: an update rewrites the real parameter -----------------------
    cfn.update_stack(StackName=stack_id, TemplateBody=template("managed"))
    updated = _wait(cfn, stack_id, {"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
                                    "UPDATE_ROLLBACK_FAILED"})
    assert updated == "UPDATE_COMPLETE", f"update of the adopted parameter: got {updated!r}"
    assert _param(ssm, name) == "managed", (
        f"after UpdateStack the adopted parameter must read 'managed', got {_param(ssm, name)!r}"
    )


def _wait(cfn, stack_id: str, terminal: set[str]) -> str:
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in terminal:
            return last
        time.sleep(4.0)
    raise AssertionError(f"stack {stack_id!r} not in {sorted(terminal)!r} after {STACK_TIMEOUT_S}s "
                         f"(last={last!r})")


def _wait_change_set(cfn, change_set_id: str) -> dict:
    deadline = time.monotonic() + STACK_TIMEOUT_S
    while time.monotonic() < deadline:
        d = cfn.describe_change_set(ChangeSetName=change_set_id)
        if d["Status"] in {"CREATE_COMPLETE", "FAILED"}:
            return d
        time.sleep(3.0)
    raise AssertionError(f"change set {change_set_id!r} not settled after {STACK_TIMEOUT_S}s")


def _param(ssm, name: str) -> str:
    """The parameter's value, or the exact error code if it cannot be read."""
    try:
        return ssm.get_parameter(Name=name)["Parameter"]["Value"]
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _delete_param(ssm, name: str) -> None:
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
