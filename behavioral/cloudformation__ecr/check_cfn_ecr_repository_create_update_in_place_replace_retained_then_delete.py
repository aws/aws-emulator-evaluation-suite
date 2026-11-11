"""cfn-ecr-repository-create-update-in-place-replace-retained-then-delete."""

from __future__ import annotations

import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ecr-repository-create-update-in-place-replace-retained-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecr"]

#: A stack operation takes seconds to a few minutes; the bound only stops a hung poll.
_STACK_S = 600.0
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """An AWS::ECR::Repository survives create, in-place update, retained replacement and delete.

    ECR reads back the templated settings and stores an uploaded layer; an ImageTagMutability change
    keeps the repository; a RepositoryName change under UpdateReplacePolicy Retain keeps the old.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ecr-repository.html
    """
    cfn = ctx.client("cloudformation")
    ecr = ctx.client("ecr")

    stack_name = ctx.unique_name("sim2real-cfnreal-ecr-")
    repo_v1 = ctx.unique_name("sim2real-cfnreal-ecr-a-")
    repo_v2 = ctx.unique_name("sim2real-cfnreal-ecr-b-")

    # The replaced repository outlives the stack, so the check deletes it itself.
    ctx.on_cleanup(lambda: _delete_repository(ecr, repo_v1))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    # ---- 1. create: CloudFormation view, ECR view, behaviour --------------------------------
    stack_id = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(repo_v1, "MUTABLE"), Tags=_TAGS
    )["StackId"]
    created = _settle(ctx, cfn, stack_id)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"create ended {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    _assert_tracks(cfn, stack_id, "Repo", repo_v1)
    repo = _repository(ecr, repo_v1)
    assert (repo["imageTagMutability"], repo["imageScanningConfiguration"]) == (
        "MUTABLE",
        {"scanOnPush": False},
    ), f"ECR must hold the templated settings, got {repo!r}"
    layer = ctx.unique_name("sim2real-layer-").encode()
    digest = _upload_layer(ecr, repo_v1, layer)

    # ---- 2. in-place update of the mutable ImageTagMutability -------------------------------
    rows = _update(ctx, cfn, stack_id, "Repo", _template(repo_v1, "IMMUTABLE"))
    _assert_updated_in_place(rows, repo_v1)
    _assert_tracks(cfn, stack_id, "Repo", repo_v1)
    updated = _repository(ecr, repo_v1)
    assert updated["imageTagMutability"] == "IMMUTABLE", f"updated mutability, got {updated!r}"
    assert (updated["repositoryArn"], updated["createdAt"]) == (
        repo["repositoryArn"],
        repo["createdAt"],
    ), f"an in-place update keeps the repository: {repo!r} -> {updated!r}"
    _assert_layer(ecr, repo_v1, digest, len(layer))

    # ---- 3. RepositoryName forces replacement; UpdateReplacePolicy Retain keeps the old one -
    rows = _update(ctx, cfn, stack_id, "Repo", _template(repo_v2, "IMMUTABLE"))
    _assert_replaced_and_retained(rows, repo_v1, repo_v2)
    _assert_tracks(cfn, stack_id, "Repo", repo_v2)
    new = _repository(ecr, repo_v2)
    assert new["imageTagMutability"] == "IMMUTABLE", f"the replacement is IMMUTABLE, got {new!r}"
    assert new["repositoryArn"] != repo["repositoryArn"], "the replacement is a new repository"
    _upload_layer(ecr, repo_v2, layer)
    old = _repository(ecr, repo_v1)
    assert old["imageTagMutability"] == "IMMUTABLE", f"the retained repository: {old!r}"
    _assert_layer(ecr, repo_v1, digest, len(layer))

    # ---- 4. DeleteStack: the repository it owns is gone -------------------------------------
    _delete_and_confirm(ctx, cfn, stack_id)
    got = _error(lambda: ecr.describe_repositories(repositoryNames=[repo_v2]))
    want = (
        "RepositoryNotFoundException",
        f"The repository with name '{repo_v2}' does not exist in the registry "
        f"with id '{ctx.account}'",
    )
    assert got == want, f"DescribeRepositories after DeleteStack: {got!r}, expected {want!r}"
    _assert_layer(ecr, repo_v1, digest, len(layer))


def _template(name: str, mutability: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Repo": {
                    "Type": "AWS::ECR::Repository",
                    # RepositoryName is create-only, so a new name replaces the repository.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "RepositoryName": name,
                        "ImageTagMutability": mutability,
                        "ImageScanningConfiguration": {"ScanOnPush": False},
                        # The uploaded layer must not block the stack's own delete.
                        "EmptyOnDelete": True,
                    },
                },
            },
        }
    )


def _repository(ecr, name: str) -> dict:
    found = ecr.describe_repositories(repositoryNames=[name])["repositories"]
    assert [r["repositoryName"] for r in found] == [name], f"ECR returned {found!r} for {name!r}"
    return found[0]


def _upload_layer(ecr, repo: str, blob: bytes) -> str:
    """Behaviour: upload blob as a layer through the layer API and see it AVAILABLE."""
    digest = "sha256:" + hashlib.sha256(blob).hexdigest()
    upload_id = ecr.initiate_layer_upload(repositoryName=repo)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(blob) - 1,
        layerPartBlob=blob,
    )
    done = ecr.complete_layer_upload(repositoryName=repo, uploadId=upload_id, layerDigests=[digest])
    assert done["layerDigest"] == digest, f"CompleteLayerUpload digest {done!r} != {digest!r}"
    _assert_layer(ecr, repo, digest, len(blob))
    return digest


def _assert_layer(ecr, repo: str, digest: str, size: int) -> None:
    layers = ecr.batch_check_layer_availability(repositoryName=repo, layerDigests=[digest])
    got = [(x["layerDigest"], x["layerAvailability"], x["layerSize"]) for x in layers["layers"]]
    assert got == [(digest, "AVAILABLE", size)], (
        f"repository {repo!r} must serve the uploaded layer, got {layers!r}"
    )


def _delete_repository(ecr, name: str) -> None:
    try:
        ecr.delete_repository(repositoryName=name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


# ===== stack helpers =====


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, *, cap_s: float, what: str, interval_s: float = 2.0):
    """Call probe() until done(result) holds and return it; ctx=None (teardown) is not budgeted."""
    timeout_s = cap_s if ctx is None else _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended while waiting for {what}; not graded")
            raise AssertionError(f"{what} not reached within {timeout_s:.0f}s; last {last!r}")
        time.sleep(interval_s)


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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
