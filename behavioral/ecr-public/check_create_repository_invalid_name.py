"""create-repository-invalid-name."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-repository-invalid-name"
GROUP = 'overly-permissive'
SERVICES = ['ecr-public']

def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_if_exists(ecr, name):
    """Teardown: force-delete the repository, tolerating one that does not exist or whose name
    the service refuses outright (a name that fails validation can never have been created)."""
    try:
        ecr.delete_repository(repositoryName=name, force=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in (
            "RepositoryNotFoundException",
            "InvalidParameterException",
        ):
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRepository and DescribeRepositories on a name that breaks the naming pattern are
    both refused InvalidParameterException with the exact pattern message and nothing is created,
    while a well-formed name is created and listed."""
    ecr = ctx.client("ecr-public")
    bad_name = "Invalid_Name!!" + ctx.unique_name("sim2real-behav-")
    bad_name_message = (
        "Invalid parameter at 'repositoryName' failed to satisfy constraint: 'must satisfy "
        "regular expression '[a-z0-9]+((\\.|_|__|-+)[a-z0-9]+)*(/[a-z0-9]+((\\.|_|__|-+)[a-z0-9]+)*)*''"
    )
    ctx.on_cleanup(lambda: _delete_if_exists(ecr, bad_name))

    error = _client_error(lambda: ecr.create_repository(repositoryName=bad_name))
    assert error.get("Code") == "InvalidParameterException", (
        f"expected InvalidParameterException, got {error.get('Code')!r}"
    )
    assert error.get("Message") == bad_name_message, f"CreateRepository message: {error.get('Message')!r}"

    # Real AWS validates repositoryName *syntax* before doing any lookup, so
    # DescribeRepositories on the same bad name also returns
    # InvalidParameterException (NOT RepositoryNotFoundException).
    error2 = _client_error(lambda: ecr.describe_repositories(repositoryNames=[bad_name]))
    assert error2.get("Code") == "InvalidParameterException", (
        f"expected InvalidParameterException on describe, got {error2.get('Code')!r}"
    )
    assert error2.get("Message") == bad_name_message, (
        f"DescribeRepositories message: {error2.get('Message')!r}"
    )

    # Positive control: the same operation, a well-formed name, succeeds -- so the rejection
    # above is attributable to the malformed name, not to CreateRepository being refused
    # outright for the caller.
    good_name = ctx.unique_name("sim2real-behav-ecrpub-validname-")
    ecr.create_repository(repositoryName=good_name)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=good_name, force=True))

    # Confirm via a full listing that the bad name never landed and the good one did.
    listed: list[str] = []
    paginator = ecr.get_paginator("describe_repositories")
    for page in paginator.paginate():
        listed.extend(r["repositoryName"] for r in page.get("repositories", []))
    assert bad_name not in listed, f"invalid-named repo was actually created: {bad_name}"
    assert good_name in listed, (
        f"the positive control repo never appeared in the listing: {good_name}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
