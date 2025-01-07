# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.6] - 2025-01-07
- Fix Chain Matches by Breaking Lines 

Example:

```shell
"data": "\n\n\n\n<CPF>"}' -> {"cpf_number": true, "cnpj_number": true, "email_address": true, "ip_address": true}
```

## [0.2.5] - 2024-09-05
- Fix (another) escape issue:

```shell
"\nandre@gmail.com" -> anonymize -> "\[REDACTED_EMAIL]"
```

## [0.2.4] - 2024-08-30
- Fix escape issue:

Current behavior:
```json
"requestBody": "{\"model\": \"gpt-4o-mini\", \"messages\": [{\"role\": \"user\", \"content\": \"\\nUnable to access the notebook \\\"[REDACTED_EMAIL]\"\\n\"}], \"temperature\": 0.7}",
```

Expected (fixed) behavior:

```json
"requestBody": "{\"model\": \"gpt-4o-mini\", \"messages\": [{\"role\": \"user\", \"content\": \"\\nUnable to access the notebook \\\"[REDACTED_EMAIL]\\"\\n\"}], \"temperature\": 0.7}",
```

## [0.2.3] - 2024-07-30
- Fix comma issue:

```shell
383.413.710-30","role" -> parser -> 38341371030role
This applies to all other mark characters like ";!?, etc)"
```

## [0.2.2] - 2024-03-01
- Fix quotes issue between matches

## [0.2.1] - 2024-02-28
- Fix comma issue between matches
- Add go build and tests on pipeline

## [0.2.0] - 2024-02-19

### Added
- Add support for Anonymization: REDACT and MASK
- Add Changelog file
- Add pre-commit hooks

## [0.1.0] - 2023-08-28

### Added
- First release of the project
- Basic functionality for detecting Brazilian PII data
