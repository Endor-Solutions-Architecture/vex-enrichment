# Endor VEX Enrichment Tool

This tool enriches VEX (Vulnerability Exploitability eXchange) documents exported from Endor Labs with additional vulnerability analysis information based on exception policies. It automatically incorporates policy-based exceptions and their associated metadata into the VEX document, making it more informative and compliant with industry standards.

## Features

Core Features:
- Authenticates with the Endor Labs API
- Exports VEX documents for packages
- Enriches VEX documents with exception policy information according to ECMA-424 including:
  - Analysis state
  - Justification tags
  - Response actions
  - Policy descriptions
  - Timestamps

Operating Modes:
1. Namespace Mode:
   - Automatically discovers all packages in a namespace (excluding GitHub Actions)
   - Retrieves findings with exceptions for all discovered packages
   - Generates a comprehensive VEX document for the entire namespace

2. Targeted Mode:
   - Processes specific packages using provided UUIDs
   - Retrieves findings with exceptions for listed packages only
   - Generates a focused VEX document for selected packages

## Prerequisites

- Python 3.6 or higher
- Access to Endor Labs API with credentials (API key and secret)

## Installation

1. Install required dependencies:
```bash
pip install -r requirements.txt
```

2. Create a `.env` file in the project root with your Endor Labs credentials (or supply as environment variables):
```
API_KEY=your_api_key
API_SECRET=your_api_secret
ENDOR_NAMESPACE=your_namespace (optional - can also be provided via a command line argument)
```

## Usage

The tool can be run in two different modes:

### 1. Namespace-only Mode
```bash
python endor_vex.py --namespace your_namespace
```
In this mode, the tool will:
- Scan your entire namespace
- Automatically discover and include ALL packages in the namespace (excluding GitHub Actions)
- Process findings and exceptions for every package found
- Generate a comprehensive VEX document for your entire namespace

This is useful when you want to:
- Get a complete overview of all packages
- Don't want to manually specify package UUIDs
- Need to process your entire namespace in one go

### 2. Targeted Package Mode
```bash
python endor_vex.py --package-uuids uuid1,uuid2,uuid3
```
In this mode, the tool will:
- Only process the specific packages you list
- Focus the analysis on just those packages
- Generate a VEX document for only the specified packages
  ```bash
  python endor_vex.py --namespace your_namespace --package-uuids uuid1,uuid2,uuid3
  ```

This is useful when you want to:
- Focus on specific packages of interest
- Generate targeted VEX documents for particular packages
- Process a subset of packages from your namespace

The script will then:
1. Authenticate with the Endor Labs API
2. Either fetch all packages (namespace mode) or use provided package UUIDs (targeted mode)
3. Retrieve findings with exceptions
4. Export and enrich a VEX document
5. Save the enriched VEX document to the `vex_exports` directory

## Output

The tool generates a JSON file in the `vex_exports` directory with the naming format:
```
vex_export_YYYYMMDD_HHMMSS.json
```

The output follows the CycloneDX VEX JSON format, enriched with analysis information from your Endor Labs exception policies.

## Tagging Exception Policies for VEX Output

To enrich your VEX documents with detailed analysis, justification, and response information, you can add tags to your Endor Labs exception policies. These tags are automatically extracted and mapped to the appropriate fields in the VEX output by this tool.

### How Tags Are Used
- **Justification tags** (e.g., `code_not_present`, `code_not_reachable`, `requires_configuration`, etc.) are mapped to the `justification` field in the VEX `analysis` section.
- **Response tags** (e.g., `can_not_fix`, `will_not_fix`, `update`, `rollback`, `workaround_available`) are mapped to the `response` field in the VEX `analysis` section.
- Tags must match the expected values to be included in the VEX output.

### Mapping: Endor Exception Reason → VEX Impact Analysis State
The `Reason` field in your Endor Labs exception policy is mapped to the `state` field in the VEX `analysis` section as follows:

| Endor Exception Reason                | VEX Impact Analysis State | Description                                                                 |
|---------------------------------------|--------------------------|-----------------------------------------------------------------------------|
| EXCEPTION_REASON_UNSPECIFIED          | in_triage                | The finding is under review or not otherwise specified.                      |
| EXCEPTION_REASON_FALSE_POSITIVE       | false_positive           | The finding is determined to be a false positive.                            |
| EXCEPTION_REASON_RISK_ACCEPTED        | exploitable              | The risk is accepted; the vulnerability is considered exploitable.           |
| EXCEPTION_REASON_IN_TRIAGE            | in_triage                | The finding is still being triaged for more information.                     |
| EXCEPTION_REASON_OTHER                | in_triage                | Other/unspecified reason; treated as in triage.                              |
| EXCEPTION_REASON_RESOLVED             | resolved                 | The issue has been resolved.                                                 |

These states are set automatically in the VEX output based on the reason you select when creating or editing an exception policy in Endor Labs.

### Adding Tags to Exception Policies
1. **Sign in to Endor Labs** and go to **Policies & Rules** > **Exception Policies** ([see official docs](https://docs.endorlabs.com/managing-policies/exception-policies/)).
2. Create or edit an exception policy.
3. In the policy editor, add your desired tags in the **Policy Tags** field.
4. Save the policy. The tags will be included in the policy metadata and picked up by this tool on the next VEX export.

#### Example: Adding a Justification Tag
- To indicate that a vulnerability is not present in your code, add the tag `code_not_present` to your exception policy.
- To indicate a response action, such as that a fix is not possible, add the tag `will_not_fix`.

#### List of Supported Tags
- **Justification tags:**
  - `code_not_present`
  - `code_not_reachable`
  - `requires_configuration`
  - `requires_dependency`
  - `requires_environment`
  - `protected_by_compiler`
  - `protected_at_runtime`
  - `protected_at_perimeter`
  - `protected_by_mitigating_control`
- **Response tags:**
  - `can_not_fix`
  - `will_not_fix`
  - `update`
  - `rollback`
  - `workaround_available`

For more details, see the [Endor Labs Exception Policies documentation](https://docs.endorlabs.com/managing-policies/exception-policies/).

## Error Handling

The script includes comprehensive error handling for:
- Missing environment variables
- API authentication failures
- Request timeouts
- Invalid responses
- File system operations

If any error occurs, the script will exit with a status code of 1 and display an appropriate error message.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT