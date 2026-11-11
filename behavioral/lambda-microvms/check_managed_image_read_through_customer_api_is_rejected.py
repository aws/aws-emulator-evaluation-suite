"""managed-image-read-through-customer-api-is-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "managed-image-read-through-customer-api-is-rejected"
GROUP = "image-namespaces"
SERVICES = ["lambda-microvms"]


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Managed and customer image lists are disjoint both ways; customer reads of a managed ARN
    answer AccessDeniedException, and ListManagedMicrovmImageVersions on an absent ARN is empty.
    """
    mvm = ctx.client("lambda-microvms")

    # POSITIVE CONTROL: the managed catalogue is readable through its own operations.
    managed = _all_managed_images(mvm)
    assert managed, "ListManagedMicrovmImages returned nothing to compare against"
    managed_arns = {i["imageArn"] for i in managed}
    for arn in managed_arns:
        assert arn.split(":")[4] == "aws", (
            f"managed image {arn!r} is not owned by the aws account segment"
        )
    probe_arn = sorted(managed_arns)[0]
    versions = mvm.list_managed_microvm_image_versions(imageIdentifier=probe_arn)
    assert versions["items"], (
        f"ListManagedMicrovmImageVersions for {probe_arn!r} returned no versions"
    )

    name = ctx.unique_name("sim2real-behav-mvm-")
    created = _create_image_with_retry(
        mvm,
        name=name,
        baseImageArn=probe_arn,
        buildRoleArn=_create_build_role(ctx),
        codeArtifact={"uri": f"s3://{name}-absent/code.zip"},
        tags={"sim2real-check": CHECK},
    )
    image_arn = created["imageArn"]
    ctx.on_cleanup(lambda: _delete_image(mvm, image_arn))

    customer_arns = {i["imageArn"] for i in _all_customer_images(mvm)}
    assert image_arn in customer_arns, (
        f"the image just created ({image_arn!r}) is missing from ListMicrovmImages"
    )
    assert not (customer_arns & managed_arns), (
        f"ListMicrovmImages leaked managed images {sorted(customer_arns & managed_arns)!r}"
    )
    assert image_arn not in {i["imageArn"] for i in _all_managed_images(mvm)}, (
        f"the customer image {image_arn!r} appeared in the managed catalogue"
    )

    # AWS names the calling principal's own ARN in the message.
    denied = (
        f"User: {ctx.client('sts').get_caller_identity()['Arn']} is not authorized to perform "
        "this operation"
    )
    code, message = _error(lambda: mvm.get_microvm_image(imageIdentifier=probe_arn))
    assert code == "AccessDeniedException", (
        f"GetMicrovmImage on the managed ARN {probe_arn!r} answered {code!r}, expected "
        f"AccessDeniedException"
    )
    assert message == denied, message
    code, message = _error(lambda: mvm.list_microvm_image_versions(imageIdentifier=probe_arn))
    assert code == "AccessDeniedException", (
        f"ListMicrovmImageVersions on the managed ARN {probe_arn!r} answered {code!r}, expected "
        f"AccessDeniedException"
    )
    assert message == denied, message
    absent = mvm.list_managed_microvm_image_versions(
        imageIdentifier=f"arn:aws:lambda:{ctx.region}:aws:microvm-image:sim2real-absent-0"
    )
    absent.pop("ResponseMetadata", None)
    assert absent == {"items": []}, (
        f"ListManagedMicrovmImageVersions on an absent managed ARN answered {absent!r}; real AWS "
        f"answers an empty page, not an error"
    )


def _all_managed_images(mvm) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        page = mvm.list_managed_microvm_images(**({"nextToken": token} if token else {}))
        items = page["items"]
        out.extend(items)
        token = page.get("nextToken")
        if not token or not items:
            break
    return out


def _create_build_role(ctx) -> str:
    """A build role of this check's own, trusted by Lambda; deleted in teardown."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-mvm-role-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": ["sts:AssumeRole", "sts:TagSession"],
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    return role_arn


def _delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_image_with_retry(mvm, timeout_s=90.0, **kwargs) -> dict:
    """CreateMicrovmImage, retried while a just-created build role is not yet visible to it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return mvm.create_microvm_image(**kwargs)
        except ClientError as exc:
            if (exc.response["Error"]["Code"] not in ("AccessDeniedException", "ValidationException")
                    or time.monotonic() >= deadline):
                raise
            time.sleep(3)


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn() raises; a success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("the call unexpectedly SUCCEEDED where real AWS rejects it")


def _all_customer_images(mvm, **kw) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        page = mvm.list_microvm_images(**kw, **({"nextToken": token} if token else {}))
        items = page["items"]
        out.extend(items)
        token = page.get("nextToken")
        if not token or not items:
            break
    return out


def _delete_image(mvm, image_arn: str) -> None:
    deadline = time.time() + 150
    while True:
        try:
            mvm.delete_microvm_image(imageIdentifier=image_arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            if time.time() >= deadline:
                raise
            time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
