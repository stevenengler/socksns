# Publishing a new release

1. Update the code.

    ```bash
    # make sure we don't include personal information (such as our home directory name) in the release
    cd /tmp

    # make sure we don't include any untracked files in the release
    git clone git@github.com:stevenengler/socksns.git
    cd socksns

    # update the version
    vim Cargo.toml
    cargo update --package socksns

    # check for errors
    cargo publish --dry-run

    # add and commit version changes with commit message, for example "Updated version to '0.2.1'"
    git add --patch
    git commit
    git push
    ```

2. After CI tests finish on GitHub, mark it as a new release.

3. Publish the crate.

    ```bash
    # make sure there are no untracked or changed files
    git status

    # publish
    cargo publish --dry-run
    cargo publish
    ```
