"""domain-rename-moves-its-custom-endpoint-url-only."""
from __future__ import annotations

import json
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-rename-moves-its-custom-endpoint-url-only"
GROUP = "domains"
SERVICES = ["cloudwatchomni"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudwatch.amazonaws.com"},
                    "Action": "sts:AssumeRole"}],
})


def _domain(ctx, cwo) -> dict:
    domain = cwo.create_domain(
        name=ctx.unique_name("sim2real-behav-cwo-dom-"), identityProviders=["IAM"]
    )["domain"]
    ctx.on_cleanup(_teardown(lambda: cwo.delete_domain(domainId=domain["domainId"]),
                             "ResourceNotFoundException"))
    return domain


def _space(ctx, cwo, domain_id: str) -> dict:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cwo-role-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST)["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    space = cwo.create_space(
        name=ctx.unique_name("sim2real-behav-cwo-space-"), domainId=domain_id, dataAccessRoleArn=role_arn
    )["space"]
    ctx.on_cleanup(_teardown(lambda: cwo.delete_space(spaceId=space["spaceId"]),
                             "ResourceNotFoundException", "AccessDeniedException"))
    return space


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control",
      "resource:account-singleton:cloudwatch-domain")
def run(ctx) -> None:
    """Renaming a domain moves the custom endpoint URL, whose first host label is the name, while
    the endpoint labelled by the domain id, the ARN and createdAt stay as they were.
    """
    cwo = ctx.client("cloudwatchomni")
    created = _domain(ctx, cwo)
    domain_id = created["domainId"]


    def labels(url):
        parts = urllib.parse.urlsplit(url)
        assert parts.scheme == "https", f"expected an https endpoint, got scheme {parts.scheme!r}"
        first, _, rest = parts.hostname.partition(".")
        return first, rest


    id_label, id_suffix = labels(created["domainEndpointUrl"])
    assert id_label == domain_id, f"the domain endpoint's first label is {id_label!r}, expected the domain id"
    assert len(created["customEndpointUrls"]) == 1, f"expected one custom endpoint, got {created['customEndpointUrls']!r}"
    name_label, name_suffix = labels(created["customEndpointUrls"][0])
    assert name_label == created["name"], f"the custom endpoint's first label is {name_label!r}, expected the name"
    assert name_suffix == id_suffix, "both endpoints must share the service host suffix"

    new_name = ctx.unique_name("sim2real-behav-cwo-dom-")
    cwo.update_domain(domainId=domain_id, name=new_name)
    got = cwo.get_domain(domainId=domain_id)["domain"]
    assert got["name"] == new_name, f"expected {new_name!r}, got {got.get('name')!r}"
    assert len(got["customEndpointUrls"]) == 1, f"expected one custom endpoint, got {got['customEndpointUrls']!r}"
    assert labels(got["customEndpointUrls"][0]) == (new_name, id_suffix), (
        f"the custom endpoint must follow the new name, got {got['customEndpointUrls']!r}"
    )
    assert got["domainEndpointUrl"] == created["domainEndpointUrl"], "the id endpoint must not move"
    assert got["domainArn"] == created["domainArn"], "the ARN must not change on rename"
    assert got["identityProviders"] == ["IAM"], f"expected ['IAM'], got {got['identityProviders']!r}"
    assert got["createdAt"] == created["createdAt"], "createdAt must not change on rename"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
