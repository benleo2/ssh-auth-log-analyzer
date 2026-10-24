# SSH Authentication Log Analyser

A Python-based cybersecurity project that analyses Linux authentication logs to identify repeated login failures, targeted usernames, and potentially suspicious authentication activity.

## Features

- Parse supported SSH authentication log entries.
- Count failed login attempts by IP address and username.
- Identify invalid usernames.
- Track successful authentication events.
- Sort authentication events chronologically.
- Generate rule-based LOW, MEDIUM, and HIGH severity alerts.

## Project Structure

```text
security-log-analyzer/
├── log_analyzer.py
├── README.md
├── sample_logs/
│   └── auth.log
├── reports/
│   └── analysis.md
└── tests/
```

## Requirements

- Python 3
- No third-party packages required for the current implementation.

## Usage

Clone the repository and enter the project directory:

```bash
git clone https://github.com/YOUR-USERNAME/ssh-auth-log-analyzer.git
cd ssh-auth-log-analyzer
```

Run the analyser against the included sample log:

```bash
python3 log_analyzer.py sample_logs/auth.log
```

Replace `YOUR-USERNAME` with your GitHub username.

## Detection

The analyser uses rule-based checks to highlight repeated failed authentication attempts and potential cases where repeated failures are followed by a successful login.

Review the generated output and `reports/analysis.md` for an example analysis and recommended investigation steps.

## Testing

The `tests/` directory contains project test code. Run the tests according to the instructions or test runner provided in that directory.

## Limitations

- Only supported log patterns are parsed; this is not a universal log analyser.
- Detection depends on the implemented rules and thresholds.
- Timestamp handling currently uses a fixed year for sorting, so logs spanning multiple years require additional handling.
- A suspicious login sequence is an alert for investigation, not proof of account compromise.
- Compatibility with different Linux authentication log formats must be tested.

## Future Improvements

- Improve support for real-world authentication log formats.
- Add chronological, time-window-based event correlation.
- Expand automated tests.
- Support structured CSV or JSON reports.
- Add configurable thresholds and command-line options.

## Disclaimer

This project is intended for educational and defensive cybersecurity analysis. Use it only with logs you are authorized to access.
