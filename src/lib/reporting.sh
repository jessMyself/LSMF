#!/usr/bin/env bash

set -Eeuo pipefail

declare -A REPORT_DATA=()
declare -a REPORT_WARNINGS=()
declare -a REPORT_RECOMMENDATIONS=()
declare -g SECURITY_SCORE=0

generate_report() {
    local report_id="${1:-$LSMF_RUN_ID}"
    local report_dir="${LSMF_REPORT_DIR}/${report_id}"
    mkdir -p "${report_dir}"
    
    log_info "Generating reports..."
    
    generate_text_report "${report_dir}/report.txt"
    generate_json_report "${report_dir}/report.json"
    generate_html_report "${report_dir}/report.html"
    
    log_success "Reports generated in: ${report_dir}"
}

generate_text_report() {
    local output_file="$1"
    
    cat > "${output_file}" << EOF
================================================================================
Linux Security Management Framework (LSMF) - Security Report
================================================================================

Report ID: ${LSMF_RUN_ID}
Generated: $(date '+%Y-%m-%d %H:%M:%S %Z')
Runtime: $(format_duration "$(get_runtime)")

================================================================================
EXECUTIVE SUMMARY
================================================================================

Security Score: ${SECURITY_SCORE}/100

System Information:
  - OS: ${OS_NAME} ${OS_VERSION}
  - Kernel: ${KERNEL_VERSION}
  - Role: ${SYSTEM_ROLE}
  - Architecture: ${CPU_ARCH}

================================================================================
SYSTEM STATUS
================================================================================

Firewall: ${FIREWALL_TYPE}
MAC System: ${MAC_SYSTEM}
Package Manager: ${PACKAGE_MANAGER}
Boot Mode: ${BOOT_MODE}
Secure Boot: ${SECURE_BOOT}

================================================================================
APPLIED HARDENING
================================================================================

EOF
    
    if [[ ${#REPORT_DATA[@]} -gt 0 ]]; then
        for key in "${!REPORT_DATA[@]}"; do
            echo "  - ${key}: ${REPORT_DATA[$key]}" >> "${output_file}"
        done
    else
        echo "  No hardening applied in this run" >> "${output_file}"
    fi
    
    cat >> "${output_file}" << EOF

================================================================================
WARNINGS
================================================================================

EOF
    
    if [[ ${#REPORT_WARNINGS[@]} -gt 0 ]]; then
        for warning in "${REPORT_WARNINGS[@]}"; do
            echo "  ! ${warning}" >> "${output_file}"
        done
    else
        echo "  No warnings" >> "${output_file}"
    fi
    
    cat >> "${output_file}" << EOF

================================================================================
RECOMMENDATIONS
================================================================================

EOF
    
    if [[ ${#REPORT_RECOMMENDATIONS[@]} -gt 0 ]]; then
        for rec in "${REPORT_RECOMMENDATIONS[@]}"; do
            echo "  * ${rec}" >> "${output_file}"
        done
    else
        echo "  No additional recommendations" >> "${output_file}"
    fi
    
    cat >> "${output_file}" << EOF

================================================================================
End of Report
================================================================================
EOF
    
    log_debug "Text report generated: ${output_file}"
}

generate_json_report() {
    local output_file="$1"
    
    local warnings_json="[]"
    if [[ ${#REPORT_WARNINGS[@]} -gt 0 ]]; then
        warnings_json="["
        for warning in "${REPORT_WARNINGS[@]}"; do
            warnings_json+="\"${warning}\","
        done
        warnings_json="${warnings_json%,}]"
    fi
    
    local recommendations_json="[]"
    if [[ ${#REPORT_RECOMMENDATIONS[@]} -gt 0 ]]; then
        recommendations_json="["
        for rec in "${REPORT_RECOMMENDATIONS[@]}"; do
            recommendations_json+="\"${rec}\","
        done
        recommendations_json="${recommendations_json%,}]"
    fi
    
    local hardening_json="{}"
    if [[ ${#REPORT_DATA[@]} -gt 0 ]]; then
        hardening_json="{"
        for key in "${!REPORT_DATA[@]}"; do
            hardening_json+="\"${key}\": \"${REPORT_DATA[$key]}\","
        done
        hardening_json="${hardening_json%,}}"
    fi
    
    cat > "${output_file}" << EOF
{
  "report_id": "${LSMF_RUN_ID}",
  "generated": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "runtime_seconds": $(get_runtime),
  "lsmf_version": "${LSMF_VERSION}",
  "security_score": ${SECURITY_SCORE},
  "system": {
    "os_name": "${OS_NAME}",
    "os_version": "${OS_VERSION}",
    "os_id": "${OS_ID}",
    "kernel": "${KERNEL_VERSION}",
    "role": "${SYSTEM_ROLE}",
    "architecture": "${CPU_ARCH}",
    "desktop_env": "${DESKTOP_ENV}",
    "virtualization": "${IS_VIRTUAL}",
    "container": "${IS_CONTAINER}",
    "cloud_provider": "${CLOUD_PROVIDER}",
    "init_system": "${INIT_SYSTEM}",
    "firewall": "${FIREWALL_TYPE}",
    "mac_system": "${MAC_SYSTEM}",
    "boot_mode": "${BOOT_MODE}",
    "secure_boot": "${SECURE_BOOT}"
  },
  "hardening_applied": ${hardening_json},
  "warnings": ${warnings_json},
  "recommendations": ${recommendations_json}
}
EOF
    
    log_debug "JSON report generated: ${output_file}"
}

generate_html_report() {
    local output_file="$1"
    
    cat > "${output_file}" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LSMF Security Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { font-size: 1.1em; opacity: 0.9; }
        .score-container {
            text-align: center;
            padding: 40px;
            background: #f8f9fa;
        }
        .score-circle {
            width: 200px;
            height: 200px;
            border-radius: 50%;
            background: conic-gradient(#4CAF50 0deg, #4CAF50 SCORE_DEGdeg, #e0e0e0 SCORE_DEGdeg);
            margin: 0 auto 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
        }
        .score-inner {
            width: 160px;
            height: 160px;
            border-radius: 50%;
            background: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 3em;
            font-weight: bold;
            color: #4CAF50;
        }
        .section {
            padding: 30px;
            border-bottom: 1px solid #e0e0e0;
        }
        .section:last-child { border-bottom: none; }
        .section h2 {
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-left: 4px solid #667eea;
            padding-left: 15px;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        .info-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            border-left: 3px solid #667eea;
        }
        .info-item strong {
            display: block;
            color: #667eea;
            margin-bottom: 5px;
        }
        .list-item {
            background: #f8f9fa;
            padding: 12px 15px;
            margin: 8px 0;
            border-radius: 5px;
            border-left: 3px solid #4CAF50;
        }
        .warning {
            border-left-color: #ff9800;
            background: #fff3e0;
        }
        .recommendation {
            border-left-color: #2196F3;
            background: #e3f2fd;
        }
        .footer {
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ LSMF Security Report</h1>
            <p>Linux Security Management Framework</p>
        </div>
        
        <div class="score-container">
            <h2>Security Score</h2>
            <div class="score-circle">
                <div class="score-inner">SECURITY_SCORE</div>
            </div>
            <p style="color: #666;">Overall System Security Rating</p>
        </div>
        
        <div class="section">
            <h2>System Information</h2>
            <div class="info-grid">
                <div class="info-item"><strong>Operating System</strong>OS_INFO</div>
                <div class="info-item"><strong>Kernel Version</strong>KERNEL_VERSION</div>
                <div class="info-item"><strong>System Role</strong>SYSTEM_ROLE</div>
                <div class="info-item"><strong>Architecture</strong>CPU_ARCH</div>
                <div class="info-item"><strong>Firewall</strong>FIREWALL_TYPE</div>
                <div class="info-item"><strong>MAC System</strong>MAC_SYSTEM</div>
                <div class="info-item"><strong>Boot Mode</strong>BOOT_MODE</div>
                <div class="info-item"><strong>Secure Boot</strong>SECURE_BOOT</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Applied Hardening</h2>
            <div id="hardening">HARDENING_ITEMS</div>
        </div>
        
        <div class="section">
            <h2>⚠️ Warnings</h2>
            <div id="warnings">WARNING_ITEMS</div>
        </div>
        
        <div class="section">
            <h2>💡 Recommendations</h2>
            <div id="recommendations">RECOMMENDATION_ITEMS</div>
        </div>
        
        <div class="footer">
            <p>Report ID: REPORT_ID</p>
            <p>Generated: TIMESTAMP</p>
            <p>LSMF Version LSMF_VERSION</p>
        </div>
    </div>
</body>
</html>
HTMLEOF
    
    local score_deg=$((SECURITY_SCORE * 36 / 10))
    sed -i "s/SCORE_DEG/${score_deg}/g" "${output_file}"
    sed -i "s/SECURITY_SCORE/${SECURITY_SCORE}/g" "${output_file}"
    sed -i "s/OS_INFO/${OS_NAME} ${OS_VERSION}/g" "${output_file}"
    sed -i "s/KERNEL_VERSION/${KERNEL_VERSION}/g" "${output_file}"
    sed -i "s/SYSTEM_ROLE/${SYSTEM_ROLE}/g" "${output_file}"
    sed -i "s/CPU_ARCH/${CPU_ARCH}/g" "${output_file}"
    sed -i "s/FIREWALL_TYPE/${FIREWALL_TYPE}/g" "${output_file}"
    sed -i "s/MAC_SYSTEM/${MAC_SYSTEM}/g" "${output_file}"
    sed -i "s/BOOT_MODE/${BOOT_MODE}/g" "${output_file}"
    sed -i "s/SECURE_BOOT/${SECURE_BOOT}/g" "${output_file}"
    sed -i "s/REPORT_ID/${LSMF_RUN_ID}/g" "${output_file}"
    sed -i "s/TIMESTAMP/$(date '+%Y-%m-%d %H:%M:%S')/g" "${output_file}"
    sed -i "s/LSMF_VERSION/${LSMF_VERSION}/g" "${output_file}"
    
    local hardening_html=""
    if [[ ${#REPORT_DATA[@]} -gt 0 ]]; then
        for key in "${!REPORT_DATA[@]}"; do
            hardening_html+="<div class='list-item'><strong>${key}:</strong> ${REPORT_DATA[$key]}</div>"
        done
    else
        hardening_html="<p>No hardening applied in this run</p>"
    fi
    sed -i "s|HARDENING_ITEMS|${hardening_html}|g" "${output_file}"
    
    local warnings_html=""
    if [[ ${#REPORT_WARNINGS[@]} -gt 0 ]]; then
        for warning in "${REPORT_WARNINGS[@]}"; do
            warnings_html+="<div class='list-item warning'>${warning}</div>"
        done
    else
        warnings_html="<p>No warnings</p>"
    fi
    sed -i "s|WARNING_ITEMS|${warnings_html}|g" "${output_file}"
    
    local recs_html=""
    if [[ ${#REPORT_RECOMMENDATIONS[@]} -gt 0 ]]; then
        for rec in "${REPORT_RECOMMENDATIONS[@]}"; do
            recs_html+="<div class='list-item recommendation'>${rec}</div>"
        done
    else
        recs_html="<p>No additional recommendations</p>"
    fi
    sed -i "s|RECOMMENDATION_ITEMS|${recs_html}|g" "${output_file}"
    
    log_debug "HTML report generated: ${output_file}"
}

add_report_data() {
    local key="$1"
    local value="$2"
    REPORT_DATA["${key}"]="${value}"
}

add_warning() {
    local warning="$1"
    REPORT_WARNINGS+=("${warning}")
}

add_recommendation() {
    local recommendation="$1"
    REPORT_RECOMMENDATIONS+=("${recommendation}")
}

calculate_security_score() {
    local score=50
    
    [[ "${FIREWALL_TYPE}" != "none" ]] && ((score+=5))
    [[ "${MAC_SYSTEM}" != "none" ]] && ((score+=10))
    [[ "${SECURE_BOOT}" == "enabled" ]] && ((score+=5))
    
    if [[ ${#REPORT_DATA[@]} -gt 0 ]]; then
        local hardening_bonus=$((${#REPORT_DATA[@]} * 2))
        [[ ${hardening_bonus} -gt 30 ]] && hardening_bonus=30
        ((score+=hardening_bonus))
    fi
    
    SECURITY_SCORE=${score}
    log_info "Security score calculated: ${SECURITY_SCORE}/100"
}

export -f generate_report generate_text_report generate_json_report
export -f generate_html_report add_report_data add_warning add_recommendation
export -f calculate_security_score
