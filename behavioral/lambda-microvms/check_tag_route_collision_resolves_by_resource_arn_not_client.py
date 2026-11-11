"""tag-route-collision-resolves-by-resource-arn-not-client."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-route-collision-resolves-by-resource-arn-not-client"
GROUP = "image-tagging"
SERVICES = ["lambda-microvms"]

# Bounded so a never-visible tag fails rather than hangs.
_TAG_VISIBILITY_BUDGET_S = 60.0

_ORIGIN = "sim2real-origin"
_VIA_MICROVMS = "sim2real-written-via-microvms"
_VIA_LAMBDA = "sim2real-written-via-lambda"


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """The lambda and lambda-microvms clients share the /2017-03-31/tags/{Resource} route, so tag reads,
    writes, untags and a not-found refusal on a microvm-image ARN agree across both clients; the
    resource type in the ARN is the only discriminator.
    """
    mvm = ctx.client("lambda-microvms")
    lam = ctx.client("lambda")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # Positive control: the `lambda` surface answers these credentials at all.
    settings = lam.get_account_settings()
    assert "AccountLimit" in settings, (
        f"GetAccountSettings returned {sorted(settings)!r} with no AccountLimit, so the "
        f"`lambda` surface is not healthy for these credentials and no later refusal on it "
        f"can be attributed to routing"
    )

    # The ARN exists as soon as CreateMicrovmImage returns and the image is never run, so the
    # codeArtifact deliberately points at nothing and no build is awaited.
    name = ctx.unique_name("sim2real-behav-mvmtagroute-")
    created = _create_image_once_role_is_visible(mvm,
        name=name,
        baseImageArn=_managed_base_image(mvm),
        buildRoleArn=_create_build_role(ctx),
        codeArtifact={"uri": f"s3://{name}-absent/code.zip"},
        tags={_ORIGIN: CHECK},
    )
    image_arn = created["imageArn"]
    ctx.on_cleanup(lambda: _delete_image(mvm, image_arn))

    # The ARN's resource type is the whole discriminator; `microvm-image` is a fixed API constant.
    parts = image_arn.split(":")
    assert len(parts) >= 7 and parts[5] == "microvm-image", (
        f"the created image ARN is {image_arn!r}; expected field 5 to be the literal "
        f"'microvm-image', which is the only thing that can route this request"
    )
    assert parts[2] == "lambda" and parts[4] == account, (
        f"the created image ARN is {image_arn!r}; expected service field 'lambda' and "
        f"account {account!r}, i.e. the same arnNamespace lambda itself uses"
    )

    # Same-client baseline: write and read through lambda-microvms.
    mvm.tag_resource(Resource=image_arn, Tags={_VIA_MICROVMS: "1"})
    expected = {_ORIGIN: CHECK, _VIA_MICROVMS: "1"}
    via_microvms = _await_tags(mvm, image_arn, expected, "after TagResource via lambda-microvms")

    # Read side: `microvm-image:` is not in lambda's TaggableResource pattern, but botocore
    # does not enforce patterns, so the server decides.
    via_lambda = lam.list_tags(Resource=image_arn)["Tags"]
    assert via_lambda == via_microvms, (
        f"GET /2017-03-31/tags/{{Resource}} answered {via_lambda!r} through the `lambda` "
        f"client and {via_microvms!r} through the `lambda-microvms` client for the same "
        f"resource {image_arn!r}; the two Smithy services share that route so the answers "
        f"must be identical"
    )

    # Write side, asserted at the other surface.
    lam.tag_resource(Resource=image_arn, Tags={_VIA_LAMBDA: "1"})
    expected = {_ORIGIN: CHECK, _VIA_MICROVMS: "1", _VIA_LAMBDA: "1"}
    _await_tags(mvm, image_arn, expected, "after TagResource via lambda")

    # Delete side, as an exact set so accumulated tags cannot pass.
    lam.untag_resource(Resource=image_arn, TagKeys=[_VIA_MICROVMS])
    expected = {_ORIGIN: CHECK, _VIA_LAMBDA: "1"}
    settled = _await_tags(mvm, image_arn, expected, "after UntagResource via lambda")

    # GetMicrovmImage is on a URI only the microvms model owns, so a separate per-service tag
    # store cannot satisfy both this read and the cross-client ones above.
    on_image = mvm.get_microvm_image(imageIdentifier=image_arn).get("tags")
    assert on_image == settled == expected, (
        f"GetMicrovmImage.tags reports {on_image!r} while ListTags reports {settled!r}; "
        f"expected both to be {expected!r}, i.e. the edits made through the `lambda` client "
        f"landed on the microvm image's own record"
    )

    # Both clients must agree on a refusal too, proving the route resolves a real resource.
    absent = (
        f"arn:aws:lambda:{ctx.region}:{account}:microvm-image:"
        f"{ctx.unique_name('sim2real-absent-')}"
    )
    code_microvms, message_microvms = _error(lambda: mvm.list_tags(Resource=absent))
    code_lambda, message_lambda = _error(lambda: lam.list_tags(Resource=absent))
    assert code_lambda == code_microvms, (
        f"ListTags on the absent resource {absent!r} answered {code_lambda!r} through the "
        f"`lambda` client and {code_microvms!r} through the `lambda-microvms` client; the "
        f"shared route must answer both the same"
    )
    assert code_microvms == "ResourceNotFoundException", (
        f"ListTags on an absent microvm-image answered {code_microvms!r}, expected "
        f"ResourceNotFoundException"
    )
    expected_message = f"MicroVMImage not found for MicroVMImageID: {absent}"
    assert message_microvms == message_lambda == expected_message, (
        f"ListTags on the absent resource {absent!r} answered message {message_lambda!r} "
        f"through the `lambda` client and {message_microvms!r} through the `lambda-microvms` "
        f"client, expected {expected_message!r} from both"
    )


def _error(fn) -> tuple[str, str]:
    """The error code and message for *fn*, raising if *fn* succeeds.

    ParamValidationError is not caught: a request that never left the SDK is not a refusal.
    """
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("the call unexpectedly SUCCEEDED where real AWS rejects it")


def _managed_base_image(mvm) -> str:
    arns: list[str] = []
    token = None
    while True:
        page = mvm.list_managed_microvm_images(**({"nextToken": token} if token else {}))
        items = page["items"]
        arns.extend(i["imageArn"] for i in items)
        token = page.get("nextToken")
        if not token or not items:
            break
    assert arns, "ListManagedMicrovmImages returned no managed base image to build from"
    return sorted(arns)[0]


def _await_tags(mvm, image_arn: str, expected: dict, when: str) -> dict:
    """ListTags at the microvms surface until it exactly equals *expected*; raises at the bound."""
    deadline = time.time() + _TAG_VISIBILITY_BUDGET_S
    seen = None
    while True:
        seen = mvm.list_tags(Resource=image_arn)["Tags"]
        if seen == expected:
            return seen
        if time.time() >= deadline:
            raise AssertionError(
                f"ListTags {when} returned {seen!r}, expected exactly {expected!r}, and it "
                f"never converged within {_TAG_VISIBILITY_BUDGET_S}s"
            )
        time.sleep(2)


def _delete_image(mvm, image_arn: str) -> None:
    """Delete the image, retrying while a still-CREATING image refuses the delete."""
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


_BUILD_ROLE_POLICY = "sim2real-mvm-build"


def _create_build_role(ctx) -> str:
    """Create the image build role and return its ARN; it grants S3 reads on sim2real- buckets
    and log writes."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-mvm-role-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_build_role(iam, role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket"],
                "Resource": ["arn:aws:s3:::sim2real-*", "arn:aws:s3:::sim2real-*/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:*:*:*",
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=_BUILD_ROLE_POLICY, PolicyDocument=json.dumps(policy)
    )
    return role_arn


def _delete_build_role(iam, role_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=_BUILD_ROLE_POLICY)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_image_once_role_is_visible(mvm, budget: float = 90.0, **kwargs) -> dict:
    """CreateMicrovmImage, retried while the freshly created build role propagates."""
    deadline = time.time() + budget
    while True:
        try:
            return mvm.create_microvm_image(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("AccessDeniedException", "ResourceNotFoundException", "ValidationException"):
                raise
            if "role" not in exc.response["Error"].get("Message", "").lower():
                raise
            if time.time() >= deadline:
                raise
            time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
