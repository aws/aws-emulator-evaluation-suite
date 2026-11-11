"""get-folder-lists-put-files."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-folder-lists-put-files"
GROUP = "data-plane"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetFolder on a commit enumerates all files previously written via PutFile at that path."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-cc-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    put1 = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"content-a",
        filePath="assets/a.txt",
        commitMessage="add a.txt",
    )
    commit1 = put1["commitId"]

    put2 = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"content-b",
        filePath="assets/b.txt",
        parentCommitId=commit1,
        commitMessage="add b.txt",
    )
    commit2 = put2["commitId"]

    # Also write a file into a nested subfolder to confirm subFolders is populated too.
    put3 = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"content-c",
        filePath="assets/nested/c.txt",
        parentCommitId=commit2,
        commitMessage="add nested c.txt",
    )
    commit3 = put3["commitId"]

    folder = cc.get_folder(
        repositoryName=repo_name, commitSpecifier=commit3, folderPath="assets"
    )

    file_names = {f["relativePath"] for f in folder.get("files", [])}
    assert file_names == {"a.txt", "b.txt"}, f"unexpected files in folder: {file_names}"

    sub_folder_names = {sf["relativePath"] for sf in folder.get("subFolders", [])}
    assert sub_folder_names == {"nested"}, f"unexpected subfolders: {sub_folder_names}"

    assert folder["commitId"] == commit3, f"GetFolder commitId {folder['commitId']!r} != {commit3!r}"
    assert folder["folderPath"] == "assets", f"GetFolder echoed folderPath {folder['folderPath']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
