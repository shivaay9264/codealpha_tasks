📌 Project Overview

This project focuses on the security auditing and remediation of a legacy internal tool used for order processing. The goal was to identify critical security flaws in the existing codebase (OrderManagement_Legacy.py), document them, and provide a fully patched version (OrderManagement_Secure.py) that adheres to secure coding standards.

The audit identified 5 major vulnerabilities, including Remote Code Execution (RCE) and SQL Injection, which have been successfully mitigated in the secure version.
📂 Project Structure
File Name	Description
OrderManagement_Legacy.py	Vulnerable Code: The original application containing security flaws (for educational analysis).
OrderManagement_Secure.py	Fixed Code: The remediated version with patches for all identified vulnerabilities.
Enterprise Security Audit Report.pdf	Audit Report: Comprehensive document detailing findings, severity, and remediation steps.
README.md	Documentation: This file.
🛡️ Vulnerability Assessment Summary

The following vulnerabilities were identified and patched:
ID	Vulnerability	Severity	Status
VULN-01	Insecure Deserialization (Pickle)	CRITICAL	✅ Patched (Replaced with JSON)
VULN-02	OS Command Injection	CRITICAL	✅ Patched (Used subprocess)
VULN-03	Path Traversal (LFI)	HIGH	✅ Patched (Input Sanitization)
VULN-04	SQL Injection	HIGH	✅ Patched (Parameterized Queries)
VULN-05	Hardcoded Secrets (AWS Keys)	MEDIUM	✅ Patched (Environment Variables)
⚙️ Setup & Installation
Prerequisites

Ensure you have Python installed. Install the required dependencies:
Bash

pip install flask

1. Running the Vulnerable App (For Testing)

WARNING: Do not run this on a public network. It is intentionally insecure.
Bash

python OrderManagement_Legacy.py

    Test SQL Injection: Access /get_order?id=1 OR 1=1

    Test Command Injection: POST to /admin/system_check with IP 8.8.8.8; whoami

2. Running the Secure App (Verified Fixes)

To run the patched version, you must set the environment variables first (simulating a production environment).

On Windows (CMD):
DOS

set AWS_ACCESS_KEY=12345-SECURE-KEY
python OrderManagement_Secure.py

On Linux/Mac:
Bash

export AWS_ACCESS_KEY=12345-SECURE-KEY
python3 OrderManagement_Secure.py

🛠️ Tools Used

    Bandit: For automated static code analysis (SAST).

    Manual Code Review: For logic flaws and architectural issues.

    Python: For scripting and remediation.

⚠️ Disclaimer

This project is for educational and assessment purposes only. The Legacy code contains live vulnerabilities. Do not deploy the legacy version in a production environment.
