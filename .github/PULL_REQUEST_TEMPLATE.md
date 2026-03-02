## Description

<!-- What does this PR do? Why? -->

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Cryptographic change (requires extra review — see CONTRIBUTING.md)
- [ ] Documentation update
- [ ] Infrastructure / tooling

## Testing

<!-- How was this tested? -->

- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] `cargo fmt --all -- --check` passes
- [ ] New tests added (if applicable)
- [ ] Governance tests: `cd governance && forge test` (if applicable)

## Security Considerations

<!-- Does this change affect any security properties?
     If yes: explain what changed and why it is safe. -->

- [ ] No security impact
- [ ] Security impact — explanation: ___

## Cryptographic Changes

If this PR touches cryptographic code, answer:

- What threat model property does this change affect?
- Has this been reviewed against the relevant academic literature?
- Are there any new `todo!()` or `unimplemented!()` stubs? If so, are they clearly marked?

## Checklist

- [ ] I have read CONTRIBUTING.md
- [ ] My code follows the project's style guidelines
- [ ] I have added/updated documentation where appropriate
- [ ] I have not introduced any new `unwrap()` calls in library code (use `?` or `Result`)
- [ ] Private keys and secrets are properly zeroized on drop
