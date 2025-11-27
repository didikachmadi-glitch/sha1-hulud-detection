# NPM Compromised Library Detector

This tool scans your project's npm dependencies and cross-checks them against a known list of compromised packages (specifically related to the "Shai Hulud" campaign and others tracked by Wiz Research).

## Overview

The script `scan_and_audit.js` performs the following actions:
1.  **Parses Local Dependencies**: Reads both `package-lock.json` (for exact installed versions) and `package.json` (for direct dependencies) to create a comprehensive list of libraries.
2.  **Fetches Threat Intelligence**: Downloads the latest list of compromised packages directly from the [Wiz Research IOCs repository](https://github.com/wiz-sec-public/wiz-research-iocs).
3.  **Audits**: Compares your local dependencies against the compromised list.
4.  **Reports**: Generates a CSV report flagging any affected libraries and indicating their source.

## Prerequisites

-   Node.js installed on your machine.
-   `package-lock.json` and `package.json` files in your project.

## Usage

You can run the script in two ways:

### 1. Default Mode
Scans for `package-lock.json` and `package.json` in the current directory:

```bash
node scan_and_audit.js
```

### 2. Custom Path
Specify the path to a specific file or directory:

-   **Directory**: Scans for both files in the specified directory.
    ```bash
    node scan_and_audit.js /path/to/project/root/
    ```
-   **File**: Uses the specified file (e.g., `package-lock.json`) and attempts to find the corresponding `package.json` in the same directory.
    ```bash
    node scan_and_audit.js /path/to/project/package-lock.json
    ```

## Output

The script generates a file named **`compromised_libraries_report.csv`** in the same directory as the script.

### Report Format

The CSV contains the following columns:
-   **Library Name**: The name of the npm package.
-   **Version**: The version installed in your project.
-   **Source**: The file where the dependency was found (`package-lock.json` or `package.json`).
-   **Is Compromised**: `YES` or `NO`.
-   **Matched Rule**: The specific version rule that triggered the match (if compromised).

## Files

-   `scan_and_audit.js`: The main script for scanning and auditing.
-   `package-lock.json`: Input file containing your project's dependency tree.
-   `package.json`: Input file containing direct dependencies.
-   `compromised_libraries_report.csv`: Output file containing the audit results.
-   `.gitignore`: Configured to exclude logs, node_modules, and generated report files.

## Disclaimer

This tool relies on the public IOC list provided by Wiz Research. It is intended to help identify known compromised packages but may not catch every possible threat. Always keep your dependencies updated and monitor security advisories.
