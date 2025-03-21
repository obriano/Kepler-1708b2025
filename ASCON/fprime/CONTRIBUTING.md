# Contributing Guidelines

F´ is a free and open source project used to build embedded software!  Are you ready to contribute?

In this file you can find basic information on contributing to [F´](https://github.com/nasa/fprime). We will walk
through how to contribute and the process contributions follow. Remember, we may ask for changes or adjustments to make
your submission the best it can be. Fear not! Your submission is still valued! You may even comment on other submissions
to help them improve.

## Ways of Contributing

The best way to contribute to F´ is to remain positive and engaged. Just about every contribution needs some improvement
before it is ready to be folded in. Stand behind your work, push it forward, and work with us!

Specific Ways to Contribute:
- [Ask a Question or Suggest Improvements](https://github.com/nasa/fprime/discussions/new)
- [Report a Bug or Mistake](https://github.com/nasa/fprime/issues/new/choose)
- [Review Contributions](https://github.com/nasa/fprime/pulls)
- Submit a Pull Request
- Contribute to Ongoing Discussions and Reviews

Feel free to contribute any way that suits your skills and enjoy.


> **Note:** [F´ Autocoder Python](https://github.com/nasa/fprime/tree/master/Autocoders) is being actively replaced
> by [FPP](https://github.com/fprime-community/fpp). Thus we will no longer accept changes to this code except for
> security and critical bug fixes done in the most minimal fashion.
>
> We do love Python fixes, please consider contributing to
> [fprime-tools](https://github.com/fprime-community/fprime-tools) or
> [fprime-gds](https://github.com/fprime-community/fprime-gds)

## Where to Start

First, contributors should build some understanding of F´. Read through the documentation, try a tutorial, or run a
reference application. Contributors can find information in our [documentation](https://fprime.jpl.nasa.gov/latest/docs). Keep
track of inconsistencies or bugs as these should be reported!

When you are ready to join discussions and submit bug reports use one of the above links!

To contribute to the F´ framework directly, consider writing
[needed documentation](https://github.com/nasa/fprime/issues?q=is%3Aissue+is%3Aopen+label%3ADocumentation) or starting
with an [easy first issue](https://github.com/nasa/fprime/issues?q=is%3Aissue+is%3Aopen+label%3A%22Easy+First+Issue%22).
When starting to modify F´ directly, ask questions, seek help, and be patient. Remember to review the project structure,
development process, and helpful tips sections below.

## Project Structure

The F´ project is designed as a base software [framework](https://github.com/nasa/fprime) with additional
[packages](https://github.com/fprime-community) designed to extend the framework. This means that occasionally we may
move contributions in or out of these packages.

Key packages include:

- [fpp](https://github.com/fprime-community/fpp): fpp development repository
- [fprime-tools](https://github.com/fprime-community/fprime-tools): `fprime-util` development repository
- [fprime-gds](https://github.com/fprime-community/fprime-gds): `fprime-gds` development repository


### F´ Repository Structure

Contributors to the [fprime](https://github.com/nasa/fprime) repository should understand the following key folders:

- [docs/UsersGuide](https://github.com/nasa/fprime/tree/devel/docs/UsersGuide): add new documentation in this or a subfolder
- [Fw](https://github.com/nasa/fprime/tree/devel/Fw): changes here will be reviewed carefully because this code is critical across F
- [Ref](https://github.com/nasa/fprime/tree/devel/Ref): update and maintain the Reference application here

## Development Process

F´ follows a standard git flow development model. Developers should start with a
[fork](https://docs.github.com/en/get-started/quickstart/fork-a-repo) of one of the F´ repositories and then develop
according to [git flow](https://docs.github.com/en/get-started/quickstart/github-flow). Remember to add an
[upstream remote](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/configuring-a-remote-repository-for-a-fork) to your fork such that you may fetch the latest changes.

For each contribution, developers should first fetch the latest changes from upstream. Then create a new branch off
`devel` and submit back to F´ using a pull request as described above.

**Preparing A New Branch**
```
git fetch upstream
git checkout upstream/devel
git checkout -b <desired branch name>
```

Once a pull request has been submitted the following process will begin.

### Submission Review

The pull request changes will be reviewed by the team and community supporting F´. Often this means that a discussion on
how to improve the submission will arise. Engage in the conversation and work with reviewers to improve the code.
Remember, F´ is flight software running in remote environments. This means we hold submissions to very high standards.
Do not fear, we are happy to work with contributors to help meet these standards!

Submission reviews can take some time for the team to complete. These reviews may take additional time for pull requests
that are very large, touch sensitive code, or have not been [discussed](https://github.com/nasa/fprime/discussions)
beforehand. Sometimes changes are determined to best fit in another repository or package. Please be patient with us and
remember we are all one team.

Anyone can review code on F´ but an approved review from a maintainer will be required to complete the submission.

### Automated Checking

Once the submission has been reviewed by a maintainer, automated checking will begin. There are many checks that must
pass on submitted code to ensure that it is not going to introduce a bug or regression to F´. These checks ensure unit
tests pass, development environments remain supported, code runs without crashing, software and documentation quality is
upheld, and more!

These checks can be a bit pedantic and this often is the point. Do your best to correct errors or ask for help. Don't be
surprised if an F´ maintainer pushes some commits to your branch to help correct minor issues (e.g. spelling errors). In
the end, these checks must pass for the submission to continue.

If something seems amiss with one of these checks ask for help on your PR and a maintainer will do their best to help
get the submission moving forward.

### Automated Checks on Reference Repositories

Some of the above-mentioned automated checks run on reference applications that are not part of the core F´ repository, such as our [tutorial repositories](https://github.com/fprime-community#tutorials). This serves two main purposes: running more tests, and making sure our suite of reference applications and tutorials do not go out-of-date.
Because of this pattern, users who submit a pull request which introduces breaking changes on _how_ F´ is used in those external repositories will need to submit associated pull requests to introduce a fix on said external repositories.

The checks are configured to run on the `devel` branch of each external repository, but will prioritize the branch `pr-<PR_NUMBER>` if it exists, with `PR_NUMBER` being the number of the pull request that has been opened in nasa/fprime.

Maintainers will gladly help you in this process.

## Final Approval and Submission

Once all corrections have been made, automated checks are passing, and a maintainer has given final approval, it is time
to contribute the submission. A maintainer will handle this final step and once complete changes should appear in the
`devel` branch. You can help this process by submitting any deferred or future work items as issues using the links
above.

## Helpful Tips

This section will describe some helpful tips for contributing to F´.

### Keep Submissions Small

Large submissions are difficult to review. Incredibly large pull requests can be very difficult to review and often need
to be broken up. Try to keep submissions small, focus on one issue or change in a pull request, and avoid lots of minor
changes across many files.

Keep in mind that editors that fix whitespace automatically can cause many small changes. Even with advanced GitHub
tools this can increase the effort required to review a submission. Be careful with the changes you are submitting.

## Run Tests

The automatic checking system will run all our unit tests and integration tests across several systems. However, this
process will take time. Try to run the unit tests locally during development before submitting a PR and use the
automatic checks as a safety net.

The tests can be run using the following commands:

```bash
# Go into the fprime directory
cp MY_FPRIME_DIRECTORY

# Run CI tests on fprime
./ci/tests/Framework.bash

# Run CI tests on the reference application
./ci/tests/Ref.bash

# Run the static analyzer with the basic configuration
# Purge unit test directory
fprime-util purge
# Generate the build files for clang-tidy. Make sure clang-tidy is installed.
fprime-util generate --ut -DCMAKE_CXX_CLANG_TIDY=clang-tidy-12
# Build fprime with the static analyzer
fprime-util build --all --ut -j16

# Run the static analyzer with additional flight code checks
# Purge release directory
fprime-util purge
# Generate the build files for clang-tidy. Make sure clang-tidy is installed.
fprime-util generate -DCMAKE_CXX_CLANG_TIDY="clang-tidy-12;--config-file=$PWD/release.clang-tidy"
# Build fprime with the static analyzer
fprime-util build --all -j16
```

## Development with modified FPP version

In case FPP needs to be locally changed, first uninstall all `fprime-fpp-*` `pip` packages, and install FPP
using the procedure mentioned in the [FPP readme](https://github.com/nasa/fpp/blob/main/compiler/README.adoc).

Then, `fprime-util generate` needs to be run using `-DFPRIME_SKIP_TOOLS_VERSION_CHECK=1`

For example, to generate and build F´:
```bash
# Go into the fprime directory
cp MY_FPRIME_DIRECTORY
# Generate the build files without checking the FPP version
fprime-util generate -DFPRIME_SKIP_TOOLS_VERSION_CHECK=1
# Build the project
fprime-util build -j4
```