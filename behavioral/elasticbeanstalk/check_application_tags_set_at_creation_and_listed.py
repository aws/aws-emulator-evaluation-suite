"""application-tags-set-at-creation-and-listed."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "application-tags-set-at-creation-and-listed"
GROUP = 'environment-data-plane'
SERVICES = ['elasticbeanstalk']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags passed to CreateApplication are retrievable via ListTagsForResource on the app ARN."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    resp = eb.create_application(
        ApplicationName=app_name,
        Tags=[{"Key": "fidelity-key", "Value": "fidelity-value"}],
    )
    ctx.on_cleanup(lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True))
    app_arn = resp["Application"]["ApplicationArn"]

    tags_resp = eb.list_tags_for_resource(ResourceArn=app_arn)
    assert tags_resp["ResourceArn"] == app_arn, (
        f"expected ListTagsForResource to echo {app_arn!r}, got {tags_resp['ResourceArn']!r}"
    )
    tags = {t["Key"]: t["Value"] for t in tags_resp["ResourceTags"]}
    assert tags.get("fidelity-key") == "fidelity-value", (
        f"expected tag fidelity-key=fidelity-value on {app_arn!r}, got tags={tags!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
