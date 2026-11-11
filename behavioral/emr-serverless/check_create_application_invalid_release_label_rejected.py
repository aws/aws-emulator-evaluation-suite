"""create-application-invalid-release-label-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-application-invalid-release-label-rejected"
GROUP = "overly-permissive"
SERVICES = ["emr-serverless"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApplication with a well-formed but non-existent EMR release label is rejected with ValidationException."""
    emrs = ctx.client("emr-serverless")
    bogus_release = "emr-0.0.0-does-not-exist"
    bogus_name = ctx.unique_name("sim2real-emrs-app-")

    code, message = _error(
        lambda: emrs.create_application(
            name=bogus_name,
            releaseLabel=bogus_release,
            type="SPARK",
            clientToken=ctx.unique_name("sim2real-emrs-tok-"),
        )
    )
    assert code == "ValidationException", (
        f"CreateApplication with non-existent release label {bogus_release!r} returned "
        f"error code {code!r}, expected 'ValidationException'"
    )
    assert message == "Type is not supported for the release label or release label does not exist", (
        f"unexpected CreateApplication invalid-release-label message: {message!r}"
    )

    # effect absent: no application with that name exists anywhere.
    names = {a["name"] for a in _list_all(emrs)}
    assert bogus_name not in names, (
        f"CreateApplication was rejected but an application named {bogus_name!r} exists in "
        f"ListApplications"
    )

    # positive control: the same request with a valid release label succeeds.
    resp = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-app-"),
        releaseLabel="emr-7.9.0",
        type="SPARK",
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
    )
    app_id = resp["applicationId"]
    ctx.on_cleanup(lambda: emrs.delete_application(applicationId=app_id))
    actual_release = emrs.get_application(applicationId=app_id)["application"]["releaseLabel"]
    assert actual_release == "emr-7.9.0", (
        f"application {app_id!r} created with releaseLabel 'emr-7.9.0' but GetApplication "
        f"reports {actual_release!r}"
    )


def _list_all(emrs, **kwargs):
    out = []
    token = None
    while True:
        params = dict(kwargs)
        if token:
            params["nextToken"] = token
        resp = emrs.list_applications(**params)
        out.extend(resp.get("applications", []))
        token = resp.get("nextToken")
        if not token:
            return out


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
