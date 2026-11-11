"""update-application-description-mutates-in-place."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "update-application-description-mutates-in-place"
GROUP = 'applications'
SERVICES = ['elasticbeanstalk']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApplication mutates the existing application object in place: the description
    changes but the application's identity (ARN, creation time) does not, so it is not a
    delete-and-recreate under the hood."""
    eb = ctx.client("elasticbeanstalk")
    name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(
        ApplicationName=name,
        Description="first",
        Tags=[{"Key": "sim2real", "Value": "eb-app-update"}],
    )
    ctx.on_cleanup(lambda _n=name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True))

    before = eb.describe_applications(ApplicationNames=[name])["Applications"]
    assert len(before) == 1, f"expected exactly one application named {name!r} after create, got {len(before)}"
    arn = before[0]["ApplicationArn"]
    created_at = before[0]["DateCreated"]
    assert before[0]["Description"] == "first", f"expected initial description 'first', got {before[0]['Description']!r}"

    resp = eb.update_application(ApplicationName=name, Description="second")
    assert resp["Application"]["ApplicationName"] == name, (
        f"expected ApplicationName {name!r} in the update response, got {resp['Application']['ApplicationName']!r}"
    )
    assert resp["Application"]["Description"] == "second", (
        f"expected updated description 'second' in the update response, got {resp['Application']['Description']!r}"
    )
    assert resp["Application"]["ApplicationArn"] == arn, (
        f"expected ApplicationArn to stay {arn!r} across UpdateApplication, "
        f"got {resp['Application']['ApplicationArn']!r}"
    )

    described = eb.describe_applications(ApplicationNames=[name])["Applications"]
    assert len(described) == 1, f"expected exactly one application named {name!r} after update, got {len(described)}"
    assert described[0]["Description"] == "second", (
        f"expected description 'second' at an independent DescribeApplications read, "
        f"got {described[0]['Description']!r}"
    )
    assert described[0]["ApplicationArn"] == arn, (
        f"expected ApplicationArn preserved across the update (mutate in place, not delete+recreate); "
        f"before={arn!r} after={described[0]['ApplicationArn']!r}"
    )
    assert described[0]["DateCreated"] == created_at, (
        f"expected DateCreated preserved across the update (mutate in place, not delete+recreate); "
        f"before={created_at!r} after={described[0]['DateCreated']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
