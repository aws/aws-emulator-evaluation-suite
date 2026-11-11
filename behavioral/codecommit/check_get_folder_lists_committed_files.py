"""get-folder-lists-committed-files."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-folder-lists-committed-files"
GROUP = "data-plane"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After committing multiple files under a path, GetFolder enumerates exactly those files
    and subfolders."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-cc-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    put_resp = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"a\n",
        filePath="dir/a.txt",
    )
    c1 = put_resp["commitId"]

    commit_resp = cc.create_commit(
        repositoryName=repo_name,
        branchName="main",
        parentCommitId=c1,
        putFiles=[
            {"filePath": "dir/b.txt", "fileContent": b"b\n"},
            {"filePath": "dir/sub/c.txt", "fileContent": b"c\n"},
            {"filePath": "unrelated/d.txt", "fileContent": b"d\n"},
        ],
    )
    c2 = commit_resp["commitId"]

    folder = cc.get_folder(repositoryName=repo_name, commitSpecifier=c2, folderPath="/dir")

    file_names = {f["relativePath"] for f in folder["files"]}
    subfolder_names = {f["relativePath"] for f in folder["subFolders"]}

    assert file_names == {"a.txt", "b.txt"}, f"GetFolder('/dir').files relativePaths {file_names!r}"
    assert subfolder_names == {"sub"}, f"GetFolder('/dir').subFolders relativePaths {subfolder_names!r}"
    assert folder["commitId"] == c2, f"GetFolder commitId {folder['commitId']!r} != {c2!r}"
    assert folder["folderPath"] == "dir", (
        f"GetFolder echoed folderPath {folder['folderPath']!r} for input '/dir' -- "
        "AWS normalizes the leading slash away"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
