"""cfn-sagemaker-model-in-place-tags-retained-replacement-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-sagemaker-model-in-place-tags-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "sagemaker"]

#: A stack operation takes seconds to a few minutes; the bound only stops a hung poll.
_STACK_S = 600.0
#: A role reaches SageMaker within seconds; the bound only stops a retry loop.
_TRUST_S = 120.0
#: A change or delete reaches every read within seconds; the bound only stops a hung poll.
_PROPAGATE_S = 60.0
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_IAM = ["CAPABILITY_IAM"]
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)
#: CreateModel's refusal of a role SageMaker cannot assume yet; CreateStack is retried on it only.
_NOT_ASSUMABLE = "Could not assume role"
#: DeleteModel's refusal of a model that does not exist; {name} is the model.
_NO_MODEL = ("ValidationException", 'Could not find model "{name}".')
_ENVIRONMENT = {"GREETING": "reality check"}
#: The AWS-owned registry of the built-in k-NN algorithm image per region. CreateModel checks
#: that the image exists; nothing pulls it, because the check never hosts the model or runs
#: inference.
_KNN_REGISTRY = {
    "af-south-1": "455444449433",
    "ap-east-1": "286214385809",
    "ap-northeast-1": "351501993468",
    "ap-northeast-2": "835164637446",
    "ap-northeast-3": "867004704886",
    "ap-south-1": "991648021394",
    "ap-southeast-1": "475088953585",
    "ap-southeast-2": "712309505854",
    "ca-central-1": "469771592824",
    "eu-central-1": "664544806723",
    "eu-north-1": "669576153137",
    "eu-west-1": "438346466558",
    "eu-west-2": "644912444149",
    "eu-west-3": "749696950732",
    "me-south-1": "249704162688",
    "sa-east-1": "855470959533",
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
}


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """An AWS::SageMaker::Model survives create, an in-place Tags update, retained replace, delete.

    DescribeModel reads back ExecutionRoleArn and PrimaryContainer and ListTags the tags; a
    ModelName change under UpdateReplacePolicy Retain keeps the old model.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sagemaker-model.html
    """
    registry = _KNN_REGISTRY.get(ctx.region)
    assert registry is not None, f"no built-in algorithm registry is listed for {ctx.region}"
    image = f"{registry}.dkr.ecr.{ctx.region}.amazonaws.com/knn:1"
    cfn = ctx.client("cloudformation")
    sm = ctx.client("sagemaker")

    stack_name = ctx.unique_name("sim2real-cfnreal-sm-")
    model_v1 = ctx.unique_name("sim2real-cfnreal-sm-a-")
    model_v2 = ctx.unique_name("sim2real-cfnreal-sm-b-")

    # The replaced model outlives the stack, so the check deletes it itself.
    ctx.on_cleanup(lambda: _delete_model(sm, model_v1))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    # ---- 1. create: CloudFormation view, SageMaker view ---------------------------------------
    stack_id = _create_retrying_role(ctx, cfn, stack_name, _template(model_v1, image, "one"))
    partition = stack_id.split(":")[1]
    arn_v1 = f"arn:{partition}:sagemaker:{ctx.region}:{ctx.account}:model/{model_v1}"
    arn_v2 = f"arn:{partition}:sagemaker:{ctx.region}:{ctx.account}:model/{model_v2}"
    # The model's Ref and physical id are its ARN.
    _assert_tracks(cfn, stack_id, "Model", arn_v1)
    role_arn = _outputs(cfn, stack_id)["RoleArn"]
    _assert_model(sm, model_v1, arn_v1, role_arn, image)
    _assert_tags(ctx, sm, arn_v1, "one")

    # ---- 2. in place: Tags is the only property that changes without a replacement ------------
    rows = _update(
        ctx, cfn, stack_id, "Model", _template(model_v1, image, "two"), Capabilities=_IAM
    )
    _assert_updated_in_place(rows, arn_v1)
    _assert_tags(ctx, sm, arn_v1, "two")
    _assert_model(sm, model_v1, arn_v1, role_arn, image)

    # ---- 3. ModelName forces replacement; UpdateReplacePolicy Retain keeps the old model ------
    rows = _update(
        ctx, cfn, stack_id, "Model", _template(model_v2, image, "two"), Capabilities=_IAM
    )
    _assert_replaced_and_retained(rows, arn_v1, arn_v2)
    _assert_tracks(cfn, stack_id, "Model", arn_v2)
    _assert_model(sm, model_v2, arn_v2, role_arn, image)
    _assert_tags(ctx, sm, arn_v2, "two")
    _assert_model(sm, model_v1, arn_v1, role_arn, image)

    # ---- 4. DeleteStack: the model it owns is gone, the retained one stays --------------------
    _delete_and_confirm(ctx, cfn, stack_id)
    want = ("ValidationException", f'Could not find model "{model_v2}".')
    _await_error(
        ctx, lambda: sm.describe_model(ModelName=model_v2), want, "DescribeModel after delete"
    )
    _assert_model(sm, model_v1, arn_v1, role_arn, image)


def _template(name: str, image: str, stage: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "ModelRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "sagemaker.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                    },
                },
                "Model": {
                    "Type": "AWS::SageMaker::Model",
                    # ModelName is create-only, so a new name replaces the model.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "ModelName": name,
                        "ExecutionRoleArn": {"Fn::GetAtt": ["ModelRole", "Arn"]},
                        "PrimaryContainer": {
                            "Image": image,
                            "Mode": "SingleModel",
                            "Environment": _ENVIRONMENT,
                        },
                        "Tags": [{"Key": "stage", "Value": stage}],
                    },
                },
            },
            "Outputs": {"RoleArn": {"Value": {"Fn::GetAtt": ["ModelRole", "Arn"]}}},
        }
    )


def _assert_model(sm, name: str, arn: str, role_arn: str, image: str) -> None:
    """SageMaker's view: DescribeModel carries exactly the template's model."""
    model = sm.describe_model(ModelName=name)
    got = {
        "ModelName": model.get("ModelName"),
        "ModelArn": model.get("ModelArn"),
        "ExecutionRoleArn": model.get("ExecutionRoleArn"),
        "PrimaryContainer": model.get("PrimaryContainer"),
        "Containers": model.get("Containers"),
        "EnableNetworkIsolation": model.get("EnableNetworkIsolation"),
    }
    want = {
        "ModelName": name,
        "ModelArn": arn,
        "ExecutionRoleArn": role_arn,
        "PrimaryContainer": {"Image": image, "Mode": "SingleModel", "Environment": _ENVIRONMENT},
        "Containers": None,
        "EnableNetworkIsolation": False,
    }
    assert got == want, f"DescribeModel must read back the template: {got!r}, want {want!r}"


def _assert_tags(ctx, sm, arn: str, stage: str) -> None:
    """ListTags carries the template's tag and the stack's tag; aws: tags are CloudFormation's."""

    def own() -> dict:
        listed = sm.list_tags(ResourceArn=arn)["Tags"]
        return {t["Key"]: t["Value"] for t in listed if not t["Key"].startswith("aws:")}

    want = {"stage": stage, "sim2real": CHECK}
    got = _poll(
        ctx, own, lambda t: t == want, cap_s=_PROPAGATE_S, what=f"ListTags on {arn} to be {want!r}"
    )
    assert got == want, f"ListTags on {arn}: {got!r}"


def _outputs(cfn, stack_id: str) -> dict:
    return {o["OutputKey"]: o.get("OutputValue") for o in _stack(cfn, stack_id).get("Outputs", [])}


def _create_retrying_role(ctx, cfn, stack_name: str, body: str) -> str:
    """CreateStack until CREATE_COMPLETE and return the StackId.

    A fresh role can reach SageMaker only seconds after IAM returns it, and no read shows when;
    a rollback for exactly that reason is deleted and created again, within _TRUST_S.
    """
    deadline = time.monotonic() + _budget_s(ctx, _TRUST_S)
    while True:
        stack_id = cfn.create_stack(
            StackName=stack_name, Capabilities=_IAM, Tags=_TAGS, TemplateBody=body
        )["StackId"]
        created = _settle(ctx, cfn, stack_id)
        if created["StackStatus"] == "CREATE_COMPLETE":
            return stack_id
        reasons = [
            e.get("ResourceStatusReason") or ""
            for e in _events(cfn, stack_id)
            if e["LogicalResourceId"] == "Model" and e["ResourceStatus"] == "CREATE_FAILED"
        ]
        retry = (
            created["StackStatus"] == "ROLLBACK_COMPLETE"
            and len(reasons) == 1
            and _NOT_ASSUMABLE in reasons[0]
            and time.monotonic() < deadline
        )
        assert retry, (
            f"create ended {created['StackStatus']!r}: {created.get('StackStatusReason')!r}; "
            f"Model failures {reasons!r}"
        )
        _delete_and_confirm(ctx, cfn, stack_id)
        time.sleep(5.0)


def _delete_model(sm, name: str) -> None:
    try:
        sm.delete_model(ModelName=name)
    except ClientError as exc:
        err = exc.response["Error"]
        if (err.get("Code"), err.get("Message")) != (_NO_MODEL[0], _NO_MODEL[1].format(name=name)):
            raise


def _await_error(ctx, fn, want: tuple[str, str], what: str) -> None:
    """Poll fn until it is refused, then assert the exact (code, message) want.

    A delete reaches every read within seconds, so a call that still succeeds is retried.
    """
    timeout_s = _budget_s(ctx, _PROPAGATE_S)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            got = (err.get("Code"), err.get("Message") or "")
            assert got == want, f"{what}: {got!r}, expected {want!r}"
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended while {what} still succeeded; not graded")
            raise AssertionError(f"{what} still succeeded after {timeout_s:.0f}s: {result!r}")
        time.sleep(2.0)


# ===== stack helpers =====


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    Teardown passes ctx=None and keeps the fixed cap: the runner's deadline does not cover it.
    """
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = None if ctx is None else ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, *, cap_s: float, what: str, interval_s: float = 2.0):
    """Call probe() until done(result) holds and return it; ctx=None (teardown) is not budgeted."""
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended while waiting for {what}; not graded")
            raise AssertionError(f"{what} not reached within {timeout_s:.0f}s; last {last!r}")
        time.sleep(interval_s)


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(ctx, cfn, stack_id: str) -> dict:
    """The stack once no operation (cleanup phase included) is in progress on it."""
    return _poll(
        ctx,
        lambda: _stack(cfn, stack_id),
        lambda s: not s["StackStatus"].endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} settled",
    )


def _physical(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _assert_tracks(cfn, stack_id: str, logical_id: str, expected: str) -> None:
    """CloudFormation's view: the stack resource carries the expected PhysicalResourceId."""
    got = _physical(cfn, stack_id, logical_id)
    assert got == expected, f"the stack must track {logical_id} as {expected!r}, got {got!r}"


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _update(ctx, cfn, stack_id: str, logical_id: str, body: str, **kw) -> list[tuple]:
    """UpdateStack to body, assert UPDATE_COMPLETE and return the update's rows for logical_id.

    A row is (ResourceStatus, ResourceStatusReason, PhysicalResourceId), oldest first.
    """
    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=body, **kw)
    stack = _settle(ctx, cfn, stack_id)
    events = _events(cfn, stack_id)[before:]
    failed = [
        (e["LogicalResourceId"], e.get("ResourceStatusReason"))
        for e in events
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"update ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}; {failed!r}"
    )
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["LogicalResourceId"] == logical_id
    ]


def _in_order(rows: list[tuple], wanted: list[tuple]) -> bool:
    """Whether every wanted row occurs in rows in that order; a None field matches any value."""
    remaining = iter(rows)
    return all(
        any(all(w is None or w == v for w, v in zip(want, row, strict=True)) for row in remaining)
        for want in wanted
    )


def _assert_updated_in_place(rows: list[tuple], physical: str) -> None:
    """The update completed on the same physical id and reported no replacement or delete."""
    assert _in_order(
        rows, [("UPDATE_IN_PROGRESS", None, None), ("UPDATE_COMPLETE", None, physical)]
    ), f"an in-place update must progress and complete on {physical!r}: {rows!r}"
    replacing = [r for r in rows if r[1] == _REPLACING or r[0].startswith("DELETE_")]
    assert replacing == [], f"an in-place update must not replace anything: {replacing!r}"


def _assert_replaced_and_retained(rows: list[tuple], old: str, new: str) -> None:
    """The update reported a replacement, completed on the new id and skipped deleting the old."""
    assert _in_order(
        rows,
        [
            ("UPDATE_IN_PROGRESS", _REPLACING, None),
            ("UPDATE_COMPLETE", None, new),
            ("DELETE_SKIPPED", None, old),
        ],
    ), (
        f"the replacement must report creating a new resource, complete as {new!r} and skip "
        f"deleting {old!r} (UpdateReplacePolicy Retain), in that order: {rows!r}"
    )
    deleted = [r for r in rows if r[0] in ("DELETE_IN_PROGRESS", "DELETE_COMPLETE")]
    assert deleted == [], f"UpdateReplacePolicy Retain must delete nothing: {deleted!r}"


def _delete_and_confirm(ctx, cfn, stack_id: str) -> None:
    """DeleteStack by StackId and assert it reaches DELETE_COMPLETE."""
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        ctx,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} deleted",
    )
    assert final == "DELETE_COMPLETE", (
        f"DeleteStack ended {final!r}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
    )


def _delete_stack(cfn, stack_name: str) -> None:
    """Teardown: delete the stack by its StackId and wait; DELETE_FAILED or a timeout raises."""
    try:
        stack_id = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {stack_name} does not exist":
            return
        raise
    status = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} settled before teardown",
    )
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} deleted",
    )
    if final != "DELETE_COMPLETE":
        raise AssertionError(
            f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
