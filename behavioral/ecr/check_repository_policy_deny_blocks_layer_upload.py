"""repository-policy-deny-blocks-layer-upload."""
from __future__ import annotations

import hashlib
import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags


def _client_error(fn):
    """Call fn(); return its (error code, error message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _code_of(exc):
    return exc.response.get("Error", {}).get("Code")


def _create_repo(ecr, ctx, name=None, **kwargs):
    """Create a repository with a verified force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: _delete_repo_verified(ecr, name))
    return resp["repository"]


def _delete_repo_verified(ecr, name, timeout_s=60):
    ecr.delete_repository(repositoryName=name, force=True)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ecr.describe_repositories(repositoryNames=[name])
        except ClientError as exc:
            if _code_of(exc) == "RepositoryNotFoundException":
                return
            raise
        time.sleep(1.0)
    raise AssertionError(f"repository {name} still present {timeout_s}s after force delete")


def _drop_policy(ecr, name):
    """Remove the repository policy; an already-absent policy or repository is fine."""
    try:
        ecr.delete_repository_policy(repositoryName=name)
    except ClientError as exc:
        code = _code_of(exc)
        if code in ("RepositoryPolicyNotFoundException", "RepositoryNotFoundException"):
            return
        raise AssertionError(f"could not remove the repository policy from {name}: {code}") from exc


def _sha256_digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


CHECK = "repository-policy-deny-blocks-layer-upload"
GROUP = 'overly-permissive'
SERVICES = ['ecr']


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A repository policy is evaluated, not just stored: an explicit Deny on InitiateLayerUpload
    blocks the push with AccessDeniedException while other operations work, and removing the
    policy restores the push."""
    ecr = ctx.client("ecr")
    repo = _create_repo(ecr, ctx, tags=[{"Key": "sim2real", "Value": CHECK}])
    name = repo["repositoryName"]

    baseline_upload = ecr.initiate_layer_upload(repositoryName=name)
    assert baseline_upload["uploadId"], f"no uploadId in the baseline upload: {baseline_upload}"
    assert baseline_upload["partSize"] > 0, (
        f"InitiateLayerUpload returned partSize {baseline_upload.get('partSize')!r}; the client "
        f"needs it to chunk a large layer"
    )
    policy_code, policy_message = _client_error(
        lambda: ecr.get_repository_policy(repositoryName=name)
    )
    assert policy_code == "RepositoryPolicyNotFoundException", "a brand-new repository must have no repository policy"
    assert policy_message == (
        f"Repository policy does not exist for the repository with name '{name}' "
        f"in the registry with id '{ctx.account}'"
    ), policy_message

    # Only InitiateLayerUpload is denied, so the policy and repository stay deletable. An ECR
    # repository policy is scoped to its repository, and any statement carrying a Resource ("*"
    # or the repository ARN) is refused with InvalidParameterException.
    def _with_resource(resource):
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "sim2realDenyLayerUpload",
                        "Effect": "Deny",
                        "Principal": {"AWS": "*"},
                        "Action": "ecr:InitiateLayerUpload",
                        "Resource": resource,
                    }
                ],
            }
        )

    for resource in ("*", repo["repositoryArn"]):
        code, message = _client_error(
            lambda r=resource: ecr.set_repository_policy(
                repositoryName=name, policyText=_with_resource(r)
            )
        )
        assert code == "InvalidParameterException", (
            f"SetRepositoryPolicy accepted a statement with Resource={resource!r} (got {code}); "
            f"a repository policy is implicitly scoped to its own repository and must not carry "
            f"a Resource element"
        )
        assert message == (
            "Invalid parameter at 'PolicyText' failed to satisfy constraint: "
            "'Invalid repository policy provided'"
        ), message
    policy_code, policy_message = _client_error(
        lambda: ecr.get_repository_policy(repositoryName=name)
    )
    assert policy_code == "RepositoryPolicyNotFoundException", "a rejected SetRepositoryPolicy must not have stored anything"
    assert policy_message == (
        f"Repository policy does not exist for the repository with name '{name}' "
        f"in the registry with id '{ctx.account}'"
    ), policy_message

    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "sim2realDenyLayerUpload",
                    "Effect": "Deny",
                    "Principal": {"AWS": "*"},
                    "Action": "ecr:InitiateLayerUpload",
                }
            ],
        }
    )
    ctx.on_cleanup(lambda: _drop_policy(ecr, name))
    put = ecr.set_repository_policy(repositoryName=name, policyText=policy)
    assert put["repositoryName"] == name, f"SetRepositoryPolicy echoed {put}"
    stored = json.loads(put["policyText"])
    assert stored["Statement"][0]["Effect"] == "Deny", (
        f"SetRepositoryPolicy did not round-trip the Deny statement: {put['policyText']}"
    )
    assert json.loads(ecr.get_repository_policy(repositoryName=name)["policyText"])[
        "Statement"
    ][0]["Sid"] == "sim2realDenyLayerUpload", "GetRepositoryPolicy returned a different document"

    # An explicit resource-policy Deny overrides every identity-based Allow. AccessDeniedException
    # is not in the ECR model; authorization errors are never modeled per operation.
    code, message = _client_error(lambda: ecr.initiate_layer_upload(repositoryName=name))
    assert code == "AccessDeniedException", (
        f"InitiateLayerUpload returned {code} with an explicit Deny on ecr:InitiateLayerUpload "
        f"in the repository policy; an explicit resource-policy Deny overrides every "
        f"identity-based Allow, so anything other than AccessDeniedException means the policy "
        f"was stored but not evaluated"
    )
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    assert message == (
        f"User: {caller_arn} is not authorized to perform: ecr:InitiateLayerUpload on resource: "
        f"{repo['repositoryArn']} with an explicit deny in a resource-based policy"
    ), message

    payload = b"sim2real-denied-push-payload"

    # Operations the policy does not deny still work on the same repository.
    assert ecr.list_images(repositoryName=name)["imageIds"] == [], (
        "ListImages must still succeed and report an empty repository"
    )
    described = ecr.describe_repositories(repositoryNames=[name])["repositories"][0]
    assert described["repositoryName"] == name, (
        f"DescribeRepositories was collaterally denied: {described}"
    )

    # Removing the Deny restores the push path.
    dropped = ecr.delete_repository_policy(repositoryName=name)
    assert dropped["repositoryName"] == name, f"DeleteRepositoryPolicy echoed {dropped}"
    policy_code, policy_message = _client_error(
        lambda: ecr.get_repository_policy(repositoryName=name)
    )
    assert policy_code == "RepositoryPolicyNotFoundException", "the policy is still readable after DeleteRepositoryPolicy"
    assert policy_message == (
        f"Repository policy does not exist for the repository with name '{name}' "
        f"in the registry with id '{ctx.account}'"
    ), policy_message

    restored = ecr.initiate_layer_upload(repositoryName=name)
    assert restored["uploadId"], f"no uploadId after the policy was removed: {restored}"
    assert restored["uploadId"] != baseline_upload["uploadId"], (
        "InitiateLayerUpload reused the pre-policy uploadId"
    )
    ecr.upload_layer_part(
        repositoryName=name,
        uploadId=restored["uploadId"],
        partFirstByte=0,
        partLastByte=len(payload) - 1,
        layerPartBlob=payload,
    )
    digest = _sha256_digest(payload)
    done = ecr.complete_layer_upload(
        repositoryName=name, uploadId=restored["uploadId"], layerDigests=[digest]
    )
    assert done["layerDigest"] == digest, (
        f"the restored push committed {done.get('layerDigest')}, expected {digest}"
    )

    # Confirm the layer landed with an independent read, not CompleteLayerUpload's echo.
    avail = ecr.batch_check_layer_availability(repositoryName=name, layerDigests=[digest])
    assert avail["layers"][0]["layerAvailability"] == "AVAILABLE", (
        f"BatchCheckLayerAvailability did not report the restored layer as AVAILABLE: {avail}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
