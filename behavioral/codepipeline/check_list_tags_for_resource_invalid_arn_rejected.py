"""list-tags-for-resource-invalid-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-resource-invalid-arn-rejected"
GROUP = 'tags'
SERVICES = ['codepipeline']


def _track_webhook(client, ctx, name):
    """Register a best-effort DeleteWebhook cleanup (PutWebhook creates a real, billable webhook)."""
    ctx.on_cleanup(lambda: client.delete_webhook(name=name))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource with a non-ARN resourceArn fails with ValidationException, while a
    well-formed ARN for a real tagged webhook lists its tag (positive control)."""
    ev = ctx.client("codepipeline")
    name = ctx.unique_name("sim2real-behav-ltfr-")
    definition = {
        "name": name,
        "targetPipeline": ctx.unique_name("sim2real-behav-absent-pipeline-"),
        "targetAction": "Source",
        "authentication": "UNAUTHENTICATED",
        "authenticationConfiguration": {},
        "filters": [{"jsonPath": "$.ref", "matchEquals": "refs/heads/main"}],
    }
    # PutWebhook needs no pipeline, bucket or role: the cheapest real, tagged, ARN-bearing resource.
    resp = ev.put_webhook(webhook=definition, tags=[{"key": "probe", "value": "ltfr"}])
    _track_webhook(ev, ctx, name)
    arn = resp["webhook"]["arn"]

    control_tags = ev.list_tags_for_resource(resourceArn=arn)["tags"]
    assert {"key": "probe", "value": "ltfr"} in control_tags, (
        f"ListTagsForResource on a well-formed webhook ARN returned {control_tags!r}, "
        f"expected the [{{'key': 'probe', 'value': 'ltfr'}}] tag set at PutWebhook"
    )

    try:
        result = ev.list_tags_for_resource(resourceArn='not-a-valid-arn')
    except ClientError as exc:
        refusal = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
    else:
        raise AssertionError(
            f"ListTagsForResource(resourceArn='not-a-valid-arn') succeeded with {result!r}, "
            f"expected ValidationException"
        )
    assert refusal == (
        "ValidationException",
        "2 validation errors detected: "
        "Value at 'resourceArn' failed to satisfy constraint: Member must satisfy regular "
        r"expression pattern: arn:aws(-[\w]+)*:codepipeline:.+:[0-9]{12}:.+; "
        "Value at 'resourceArn' failed to satisfy constraint: Member must have length "
        "greater than or equal to 37",
    ), refusal


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
