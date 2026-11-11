"""create-application-same-client-token-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-application-same-client-token-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["emr-serverless"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Retrying CreateApplication with the same clientToken but different parameters is rejected with ConflictException,
    the original application is left untouched, and replaying the identical request succeeds idempotently."""
    emrs = ctx.client("emr-serverless")
    token = ctx.unique_name("sim2real-emrs-tok-")
    name1 = ctx.unique_name("sim2real-emrs-app-a-")
    name2 = ctx.unique_name("sim2real-emrs-app-b-")

    resp1 = emrs.create_application(
        name=name1,
        releaseLabel="emr-7.9.0",
        type="SPARK",
        clientToken=token,
        tags={"sim2real-marker": "same-client-token-conflict"},
    )
    app_id1 = resp1["applicationId"]
    ctx.on_cleanup(lambda: emrs.delete_application(applicationId=app_id1))

    code, message = _error(
        lambda: emrs.create_application(
            name=name2, releaseLabel="emr-7.9.0", type="SPARK", clientToken=token
        )
    )
    assert code == "ConflictException", (
        f"expected ConflictException reusing clientToken {token!r} with different "
        f"params, got {code!r}"
    )
    assert message == "Request did not match the original", (
        f"unexpected ConflictException message: {message!r}"
    )

    # effect absent: the original application's name was not overwritten and no second application appeared.
    unchanged = emrs.get_application(applicationId=app_id1)["application"]
    assert unchanged["name"] == name1, (
        f"expected original application {app_id1} to keep name {name1!r}, "
        f"got {unchanged['name']!r}"
    )
    live_names = {
        a["name"]
        for a in emrs.list_applications(states=["CREATING", "CREATED"]).get("applications", [])
    }
    assert name2 not in live_names, (
        f"expected {name2!r} to never appear in list_applications after the "
        f"rejected conflicting create, but it did"
    )

    # positive control: replaying the *identical* request is idempotent and returns the same application.
    replay = emrs.create_application(
        name=name1,
        releaseLabel="emr-7.9.0",
        type="SPARK",
        clientToken=token,
        tags={"sim2real-marker": "same-client-token-conflict"},
    )
    assert replay["applicationId"] == app_id1, (
        f"expected idempotent replay of the identical request to return {app_id1}, "
        f"got {replay['applicationId']!r}"
    )

    # terminal read: independent of both the conflicting and the replayed create calls.
    final = emrs.get_application(applicationId=app_id1)["application"]
    assert final["name"] == name1, (
        f"expected {app_id1} to still be named {name1!r} after the idempotent "
        f"replay, got {final['name']!r}"
    )
    matching_ids = [
        a["id"]
        for a in emrs.list_applications(states=["CREATING", "CREATED"]).get("applications", [])
        if a["name"] == name1
    ]
    assert matching_ids == [app_id1], (
        f"expected exactly one CREATING/CREATED application named {name1!r} "
        f"({app_id1}), found {matching_ids}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
