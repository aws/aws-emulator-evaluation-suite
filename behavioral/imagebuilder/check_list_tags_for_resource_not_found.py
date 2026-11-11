"""list-tags-for-resource-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["imagebuilder"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on a well-formed ARN that was never created fails with NotFoundException
    "Resource was not found", while on a real component it returns the component's tag."""
    ib = ctx.client("imagebuilder")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bogus_name = ctx.unique_name("sim2real-missing-")
    bogus_arn = f"arn:aws:imagebuilder:{ctx.region}:{account_id}:component/{bogus_name}/1.0.0/1"

    code, message = _error(lambda: ib.list_tags_for_resource(resourceArn=bogus_arn))
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    assert message == "Resource was not found", f"expected message 'Resource was not found', got {message!r}"

    # positive control: the same call against a real component succeeds and reflects its tags
    component_arn = _create_component(ctx)
    got = ib.list_tags_for_resource(resourceArn=component_arn)["tags"]
    assert got.get("sim2real-check") == CHECK, (
        f"positive control failed: listing tags on real component {component_arn} returned {got!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING a resourceArn real AWS rejects is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected ListTagsForResource to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_component(ctx, version: str = "1.0.0", platform: str = "Linux") -> str:
    ib = ctx.client("imagebuilder")
    name = ctx.unique_name("sim2real-ib-comp-")
    doc = (
        f"name: {name}\n"
        "description: positive-control component for list-tags-for-resource-not-found\n"
        "schemaVersion: 1.0\n"
        "phases:\n"
        "  - name: build\n"
        "    steps:\n"
        "      - name: UpdateOS\n"
        "        action: UpdateOS\n"
    )
    resp = ib.create_component(
        name=name,
        semanticVersion=version,
        platform=platform,
        data=doc,
        clientToken=str(uuid.uuid4()),
        tags={"sim2real-check": CHECK},
    )
    arn = resp["componentBuildVersionArn"]
    ctx.on_cleanup(lambda: ib.delete_component(componentBuildVersionArn=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
