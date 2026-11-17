"""get-deployment-for-an-unknown-identifier-is-not-found."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-deployment-for-an-unknown-identifier-is-not-found"
GROUP = "negative-classes"
SERVICES = ["network-security-manager"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDeployment on a well-formed but unknown deployment ARN is refused with
    ResourceNotFoundException, and ListDeployments never surfaces the identifier.
    """
    nsm = ctx.client("network-security-manager")
    fake_id = "".join(c for c in ctx.unique_name("simbehavnsmmissingdeployment") if c.isalnum())
    fake_arn = f"arn:aws:network-security-manager:{ctx.region}:{ctx.account}:deployment:{fake_id}"

    code, message = _error(lambda: nsm.get_deployment(deploymentIdentifier=fake_arn))
    assert code == "ResourceNotFoundException", (
        f"GetDeployment for an unknown identifier gave {code!r}, expected ResourceNotFoundException"
    )
    assert message == "The requested resource was not found.", f"unexpected message {message!r}"

    # The call path itself works (same setup, nothing broken): a listing read succeeds and
    # never surfaces the identifier that was just refused as not found.
    deployment_ids = set()
    for page in nsm.get_paginator("list_deployments").paginate():
        deployment_ids.update(d["deploymentId"] for d in page["deployments"])
    assert fake_id not in deployment_ids, (
        f"ListDeployments unexpectedly included the never-created id {fake_id!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
