"""brand-profile-names-are-not-unique."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "brand-profile-names-are-not-unique"
GROUP = "brand-profiles"
SERVICES = ["endusermessaging"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two brand profiles may share one name: both creates succeed with distinct ids and both
    appear in ListBrandProfiles under that name.
    """
    eum = ctx.client("endusermessaging")
    shared = ctx.unique_name("sim2real-behav-eum-samename-")
    ids = []
    for _ in range(2):
        bpid = eum.create_brand_profile(brandProfileName=shared)["brandProfileId"]
        ctx.on_cleanup(_teardown(lambda b=bpid: eum.delete_brand_profile(brandProfileId=b),
                                 "ResourceNotFoundException"))
        ids.append(bpid)
    assert ids[0] != ids[1], f"two creates must mint two ids, got {ids!r}"

    names = {}
    for page in eum.get_paginator("list_brand_profiles").paginate():
        for item in page["brandProfiles"]:
            if item["brandProfileId"] in ids:
                names[item["brandProfileId"]] = item["brandProfileName"]
    assert names == {ids[0]: shared, ids[1]: shared}, (
        f"both profiles must be listed under the shared name, got {names!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
