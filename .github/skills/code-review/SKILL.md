---
name: code-review
description: "Review changes to this Microsoft Azure Attestation sample repository for correctness, security, compatibility, regressions, and missing tests. Use for code review, pull request review, diff review, security review, or pre-merge validation across C++, C#, PowerShell, shell, CMake, and documentation."
argument-hint: "Optional review target, such as the current diff, a branch, commit, or pull request"
---

# Code Review

Review changes to this repository as security-sensitive sample code intended for a public audience.

## Scope

1. Determine the requested review target. If none is given, review the current working-tree diff.
2. Inspect the changed files and enough owning code, call sites, tests, and documentation to establish intended behavior.
3. Treat `maa.jwt.verifier/vendors/vcpkg` as third-party vendored code unless the requested change intentionally modifies it.
4. Ignore generated `bin`, `obj`, build-output, and package-cache files unless they are intentionally part of the change or reveal an artifact-management problem.
5. Do not modify files during a review unless the user explicitly asks for fixes.

## Public Repository Safety

Before reporting or creating any artifact:

- Use only information present in the repository, the review target, or verified public documentation.
- Do not expose credentials, access tokens, private keys, connection strings, tenant or subscription identifiers, private endpoints, internal hostnames, unpublished incident details, usernames, local absolute paths, or session/tool metadata.
- Do not expose personal data or PII, including names, email addresses, phone numbers, account identifiers, IP addresses, device identifiers, or identity claims. Use synthetic placeholders in examples.
- Inspect the complete diff, added fixtures, configuration, documentation, and generated artifacts for secrets and PII. Do not rely only on filenames or an automated scanner.
- Do not reproduce a discovered secret. Redact it, identify only its location and type, recommend removal from history where applicable, and recommend rotation or revocation.
- Treat JWTs, quotes, certificates, logs, and attestation evidence as potentially sensitive. Check their decoded claims and metadata before recommending that they be committed. A signed JWT is not automatically safe to publish.
- Do not cite an issue, pull request, commit, or URL unless it was fetched and confirmed during the review. Omit unverified references.
- Do not invent test results, runtime behavior, approvals, ownership, requirements, supported versions, or security guarantees. Distinguish verified facts from assumptions and unresolved questions.
- Keep temporary investigation output outside tracked source directories and remove it when the review is complete.

## Ownership And Approval

- Check repository ownership rules, required reviewers, branch protection, and actual review status when that information is available.
- Confirm that security-sensitive, attestation, cryptographic, dependency, and release changes have approval from the owners required by repository policy.
- Do not infer ownership from commit history, filenames, or familiarity with the code. Do not claim approval unless the approval record was verified.
- If no root `CODEOWNERS`, authoritative ownership policy, or review status is available, report owner approval as unverified and require a maintainer to confirm it before merge.

## Review Priorities

Prioritize concrete defects over style preferences. Review in this order:

1. Security vulnerabilities and weakened trust decisions.
2. Incorrect attestation, certificate, JWT, or cryptographic validation.
3. Behavioral regressions, crashes, data corruption, and fail-open error handling.
4. Platform, dependency, build, and deployment regressions.
5. Missing tests or documentation that allow a material defect to escape.

Do not report speculative concerns without a plausible failure path. Verify that each finding is introduced by or materially affected by the reviewed change.

## Attestation And Cryptography Checks

- Keep the attested workload claims separate from the evidence protecting the MAA signing certificate. Do not infer one TEE type from the other.
- Require cryptographic verification before trusting JWT claims, certificate identity, enclave measurements, policy results, or runtime data.
- Check algorithm allowlists, issuer and audience requirements, validity times, key selection, certificate-chain validation, trusted roots, and evidence-format dispatch.
- Ensure unknown algorithms, OIDs, evidence formats, TEE kinds, malformed encodings, missing claims, and verification errors fail closed.
- Review `jku`, `kid`, certificate, and network handling for SSRF, untrusted redirects, key confusion, ambiguous key selection, and TLS validation failures.
- Check nonce, report-data, enclave-held-data, policy-hash, measurement, signer, product ID, security version, and debug-state comparisons where the workflow depends on them.
- Do not accept extension presence, parsing success, or a decoded payload as proof of cryptographic validity.
- Prefer established platform or cryptographic libraries over custom implementations. Review buffer lengths, ownership, integer conversions, base64 handling, and error propagation in native code.
- Confirm comments and documentation describe legacy and current evidence formats accurately without presenting a sample verifier as production-complete.

## Language And Build Checks

### C++ And CMake

- Check pointer and buffer lifetimes, bounds, null handling, resource cleanup on every success and failure path, exception boundaries, and OpenSSL/Open Enclave return values.
- Check every allocation and acquired handle for a matching release. Prefer RAII and ownership-expressing types; flag leaks, double frees, use-after-free, mismatched allocators, and dangling references.
- When native ownership or allocation behavior changes, run an available leak detector or sanitizer such as AddressSanitizer, LeakSanitizer, or Valgrind. If none is available, state that leak testing was not performed.
- Preserve warning-as-error compatibility on Windows and Linux.
- Check platform conditions, target names, linked libraries, architecture assumptions, and CMake variable spelling.

### C# And .NET

- Check nullable behavior, async flow, disposal of `IDisposable` and `IAsyncDisposable` resources, unmanaged handles, event-handler lifetime, exception handling, token-validation configuration, and cryptographic API usage.
- Flag unsupported target frameworks and vulnerable or incompatible package changes when they affect the reviewed behavior.

### PowerShell, Shell, And Command Files

- Require quoted paths, terminating error behavior, subprocess exit-code checks, secure temporary directories, and cleanup on failure.
- Scrutinize privileged package installation, repository/key configuration, and environment mutation.
- For downloaded executable content, require HTTPS, version pinning, integrity verification, and failure on checksum mismatch.
- Avoid predictable privileged paths and execution of files writable by other users.

### Documentation And Samples

- Test commands from the directory and shell stated by the documentation.
- Check README claims against the current implementation, scripts, dependency versions, build output, and observed runtime behavior.
- Check that prerequisites, supported platforms, output paths, security limitations, expected successes, and expected failures are explicit and accurate.
- Ensure all affected READMEs and samples are updated together. Flag stale commands, paths, versions, output text, or compatibility claims.
- Do not publish generated tokens or evidence merely to make instructions appear complete. Include fixtures only when their purpose, disclosure risk, provenance, and expected result are clear.

## Validation

Run the narrowest relevant checks available for changed components. Read setup scripts before executing them because they may download packages, alter repositories, or require elevated access.

For code or build-system changes, a successful compile alone is insufficient: build the affected target and run the affected workflow or executable with representative valid and invalid inputs. Confirm its output and exit status match the documented behavior. If the required environment, hardware, service, credentials, or fixture is unavailable, record the missing runtime validation as a merge risk rather than assuming success.

- Native verifier on Windows: use `maa.jwt.verifier/win_setup_and_build.ps1`, then run the produced verifier with an appropriate fixture.
- Native verifier on Ubuntu 22.04: use `maa.jwt.verifier/ubuntu_setup_and_build.sh`, then run the produced verifier with an appropriate fixture.
- .NET projects: run `dotnet build` on the affected project or solution and execute the narrowest applicable sample or test.
- Scripts: perform syntax checks where available and exercise failure paths without exposing credentials.
- Documentation-only changes: validate links, commands, paths, shell syntax, factual claims against the implementation, and `git diff --check`.

Do not claim a check passed unless it was run successfully and its result was inspected. Report the exact scope of completed checks, skipped checks and their reason, and any environment-specific coverage gap.

## Review Output

Present findings first, ordered by severity:

- **Critical**: exploitable trust or credential compromise, unsafe code execution, or systemic verification bypass.
- **High**: security boundary bypass, fail-open validation, or likely severe runtime failure.
- **Medium**: meaningful correctness, compatibility, or reliability regression.
- **Low**: limited defect with concrete impact. Do not use this category for cosmetic preferences.

For each finding, include:

1. A concise title and severity.
2. A workspace-relative file and line reference.
3. The concrete failure or attack scenario.
4. Why existing checks do not prevent it.
5. The smallest appropriate remediation.

After findings, list open questions or assumptions, then summarize validation performed. If there are no findings, state that clearly and identify remaining test gaps or residual risk.

End with a merge-readiness statement that separately reports:

- Security and privacy review status.
- Build status for each affected platform.
- Runtime and negative-path test status.
- Memory-leak test status when native ownership changed.
- README and sample consistency status.
- Required owner approval status.

Use `verified`, `failed`, or `not verified` for each status. Never replace missing evidence with an assumption.