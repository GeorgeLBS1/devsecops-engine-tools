from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Category,
    Finding,
)
from datetime import datetime
from dataclasses import dataclass
import json
import re

@dataclass
class BearerDeserealizator:
    @classmethod
    def get_list_finding(cls,
                         scan_result_path) -> "list[Finding]":
        findings = []
        with open(scan_result_path, encoding='utf-8') as arc:
            try:
                data = json.load(arc)
                severity = list(data.keys())
            except:
                return findings
            
            description_pattern = r"(?<=## Description\n)(.*?)(?=##)"

            for sev in severity:
                vulnerabilities = data[sev]
                for vul in vulnerabilities:
                    description = re.search(description_pattern, vul["description"], flags=re.DOTALL).group(1).strip()
                    chunks = [description[i : i + 70] for i in range(0, len(description), 70)]

                    formatted_description = "\n".join(chunks)
                    formatted_id = vul["id"] + ": " + (", ").join([f"CWE-{cwe}" for cwe in vul["cwe_ids"]])

                    finding = Finding(
                        id=formatted_id,
                        cvss="",
                        where=vul["full_filename"],
                        description=formatted_description,
                        severity=sev.lower(),
                        identification_date=datetime.now().strftime("%d%m%Y"),
                        published_date_cve=None,
                        module="engine_code",
                        category=Category.VULNERABILITY,
                        requirements="",
                        tool="Bearer"
                    )
                    findings.append(finding)
        
        return findings
        