import json
import os
import base64
from datetime import datetime

def generate_html_report(scan_results_file="scan_report.json", shap_image_path="reports/figures/shap_summary.png", output_file="security_report.html"):
    """
    Generates a rich HTML report from scan results and SHAP explanations.
    """
    print("Generating HTML Security Report...")
    
    # Load Scan Results
    try:
        with open(scan_results_file, 'r') as f:
            results = json.load(f)
            # Handle case where results is a list (legacy format)
            if isinstance(results, list):
                results = {
                    "results": results,
                    "total_files": len(results),
                    "vulnerable_files": sum(1 for r in results if r.get('status') == 'VULNERABLE'),
                    "scan_duration": "N/A"
                }
    except FileNotFoundError:
        print("No scan results found. Skipping report.")
        return

    # Load SHAP Image as Base64
    if os.path.exists(shap_image_path):
        with open(shap_image_path, "rb") as img_file:
            shap_b64 = base64.b64encode(img_file.read()).decode('utf-8')

    # Calculate Stats
    total_files = results.get("total_files", 0)
    vulnerable_files = results.get("vulnerable_files", 0)
    safe_files = total_files - vulnerable_files
    scan_duration = results.get("scan_duration", "N/A")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # --- Calculate Statistics for Dashboard ---
    vuln_types = {}
    vulnerable_files_list = []
    safe_files_list = []

    for res in results.get("results", []):
        if res.get('status') == 'VULNERABLE':
            vulnerable_files_list.append(res)
            
            # Get findings list
            findings = res.get('details', {}).get('dangerous_calls', [])
            
            if findings:
                # Count specific vulnerability types
                for finding in findings:
                    if isinstance(finding, dict):
                        v_type = finding['type']
                        vuln_types[v_type] = vuln_types.get(v_type, 0) + 1
                    else:
                        # Fallback for old string format
                        vuln_types['Generic Risk'] = vuln_types.get('Generic Risk', 0) + 1
            else:
                # If no specific findings, categorize as ML Prediction
                vuln_types['ML Predicted Risk'] = vuln_types.get('ML Predicted Risk', 0) + 1
        else:
            safe_files_list.append(res)

    # Prepare data for JS
    vuln_labels = list(vuln_types.keys())
    vuln_counts = list(vuln_types.values())

    # HTML Template (Embedded for simplicity)
    html_content = f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reporte de Seguridad de Software - Proyecto Minería de Datos</title>
        <style>
            :root {{
                --primary: #2c3e50;
                --secondary: #34495e;
                --accent: #3498db;
                --danger: #e74c3c;
                --success: #27ae60;
                --warning: #f39c12;
                --light: #ecf0f1;
                --dark: #2c3e50;
                --bg: #f4f7f6;
                --card-bg: #ffffff;
                --text: #333333;
                --text-muted: #7f8c8d;
                --border: #e0e0e0;
                --shadow: 0 4px 6px rgba(0,0,0,0.05);
                --shadow-hover: 0 8px 15px rgba(0,0,0,0.1);
                --radius: 12px;
            }}

            body {{ font-family: 'Segoe UI', 'Inter', system-ui, -apple-system, sans-serif; margin: 0; padding: 0; background-color: var(--bg); color: var(--text); line-height: 1.6; }}
            
            /* Header */
            header {{ background: linear-gradient(135deg, var(--primary), var(--secondary)); color: white; padding: 40px 20px; text-align: center; box-shadow: 0 4px 12px rgba(0,0,0,0.15); margin-bottom: 40px; }}
            header h1 {{ margin: 0; font-size: 2.8em; font-weight: 700; letter-spacing: -0.5px; }}
            .subtitle {{ opacity: 0.9; margin-top: 10px; font-size: 1.2em; font-weight: 300; }}
            
            /* Layout */
            .container {{ max-width: 1200px; margin: 0 auto; padding: 0 20px; }}
            
            /* Stats Grid */
            .stats-row {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 25px; margin-bottom: 40px; }}
            .stat-card {{ background: var(--card-bg); padding: 25px; border-radius: var(--radius); text-align: center; box-shadow: var(--shadow); transition: transform 0.2s ease; border: 1px solid var(--border); }}
            .stat-card:hover {{ transform: translateY(-5px); box-shadow: var(--shadow-hover); }}
            .stat-number {{ font-size: 3em; font-weight: 800; line-height: 1; margin-bottom: 10px; }}
            .stat-label {{ color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.85em; letter-spacing: 1px; }}
            
            /* Charts Grid */
            .dashboard-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(450px, 1fr)); gap: 30px; margin-bottom: 50px; }}
            .chart-card {{ background: var(--card-bg); padding: 30px; border-radius: var(--radius); box-shadow: var(--shadow); border: 1px solid var(--border); }}
            .chart-card h3 {{ margin-top: 0; color: var(--primary); font-size: 1.3em; border-bottom: 2px solid var(--light); padding-bottom: 15px; margin-bottom: 20px; }}
            
            /* Section Titles */
            .section-title {{ display: flex; align-items: center; gap: 15px; margin: 60px 0 30px; color: var(--primary); font-size: 2em; font-weight: 700; }}
            .section-title::after {{ content: ''; flex: 1; height: 2px; background: var(--border); margin-left: 20px; opacity: 0.5; }}
            
            /* Finding Cards */
            .finding-card {{ background: var(--card-bg); border-radius: var(--radius); box-shadow: var(--shadow); margin-bottom: 30px; overflow: hidden; border: 1px solid var(--border); transition: all 0.3s ease; }}
            .finding-card:hover {{ box-shadow: var(--shadow-hover); transform: translateY(-2px); }}
            .finding-card.vulnerable {{ border-top: 6px solid var(--danger); }}
            .finding-card.safe {{ border-top: 6px solid var(--success); }}
            
            .card-header {{ padding: 20px 25px; background: #fcfcfc; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px; }}
            .file-name {{ font-size: 1.3em; font-weight: 700; color: var(--primary); font-family: 'Consolas', 'Monaco', monospace; }}
            
            .card-body {{ padding: 25px; }}
            
            /* Detailed Findings */
            .finding-detail {{ background: #fff; border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px; border-left: 5px solid var(--warning); box-shadow: 0 2px 4px rgba(0,0,0,0.02); }}
            .finding-detail.critical {{ border-left-color: var(--danger); }}
            .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }}
            .finding-type {{ font-weight: 800; font-size: 1.1em; color: var(--danger); }}
            .line-badge {{ background: var(--secondary); color: white; padding: 4px 10px; border-radius: 6px; font-size: 0.85em; font-weight: 600; }}
            
            .code-block {{ background: #282c34; color: #abb2bf; padding: 15px; border-radius: 6px; font-family: 'Consolas', monospace; font-size: 0.9em; overflow-x: auto; margin: 15px 0; border: 1px solid #1e2127; }}
            .remediation-box {{ background: #f0fdf4; color: #166534; padding: 15px; border-radius: 6px; border: 1px solid #bbf7d0; font-size: 0.95em; display: flex; gap: 10px; align-items: start; }}
            
            /* Badges */
            .badge {{ padding: 8px 16px; border-radius: 30px; font-size: 0.85em; font-weight: 800; text-transform: uppercase; letter-spacing: 1px; display: inline-block; }}
            .badge-vuln {{ background-color: #fce8e6; color: var(--danger); border: 1px solid #fad2cf; }}
            .badge-safe {{ background-color: #e6f4ea; color: var(--success); border: 1px solid #ceead6; }}
            
            /* Safe Table */
            .safe-table-container {{ background: var(--card-bg); border-radius: var(--radius); box-shadow: var(--shadow); overflow: hidden; border: 1px solid var(--border); }}
            .safe-table {{ width: 100%; border-collapse: collapse; }}
            .safe-table th {{ background: #f8f9fa; padding: 18px 25px; text-align: left; color: var(--text-muted); font-weight: 700; text-transform: uppercase; font-size: 0.85em; letter-spacing: 0.5px; border-bottom: 2px solid var(--border); }}
            .safe-table td {{ padding: 18px 25px; border-bottom: 1px solid var(--border); color: var(--text); font-size: 0.95em; }}
            .safe-table tr:last-child td {{ border-bottom: none; }}
            .safe-table tr:hover td {{ background-color: #f8f9fa; }}
            
            /* SHAP */
            .shap-container {{ text-align: center; margin: 30px 0; }}
            .shap-img {{ max-width: 100%; border-radius: 8px; box-shadow: var(--shadow); border: 1px solid var(--border); }}
            .shap-guide {{ background: #f0f9ff; padding: 25px; border-radius: var(--radius); border: 1px solid #bae6fd; margin-top: 30px; }}
            .shap-guide h3 {{ color: #0369a1; margin-top: 0; font-size: 1.2em; }}
            
            footer {{ text-align: center; padding: 40px; color: var(--text-muted); font-size: 0.9em; border-top: 1px solid var(--border); margin-top: 60px; }}
            
            @media (max-width: 768px) {{
                .stats-row {{ grid-template-columns: 1fr 1fr; }}
                .dashboard-grid {{ grid-template-columns: 1fr; }}
                .card-header {{ flex-direction: column; align-items: flex-start; }}
            }}
        </style>
    </head>
    <body>
        <header>
            <h1>🛡️ Dashboard de Seguridad</h1>
            <div class="subtitle">Análisis Automatizado de Vulnerabilidades</div>
        </header>

        <div class="container">
            
            <!-- Key Metrics Row -->
            <div class="stats-row">
                <div class="stat-card">
                    <div class="stat-number" style="color: #e74c3c">{vulnerable_files}</div>
                    <div class="stat-label">Archivos Críticos</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" style="color: #27ae60">{safe_files}</div>
                    <div class="stat-label">Archivos Seguros</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" style="color: #3498db">{len(vuln_types)}</div>
                    <div class="stat-label">Tipos de Riesgo</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{scan_duration}s</div>
                    <div class="stat-label">Duración</div>
                </div>
            </div>

            <!-- Charts Row -->
            <div class="dashboard-grid">
                <div class="chart-card">
                    <h3 style="text-align:center; margin-bottom:15px;">Distribución de Archivos</h3>
                    <canvas id="filesChart"></canvas>
                </div>
                <div class="chart-card">
                    <h3 style="text-align:center; margin-bottom:15px;">Top Vulnerabilidades</h3>
                    <canvas id="vulnChart"></canvas>
                </div>
            </div>

            <!-- SHAP Section -->
            <h2 class="section-title">🧠 Análisis de Inteligencia Artificial</h2>
            <div class="chart-card">
                <div style="text-align: center;">
                    {f'<img src="data:image/png;base64,{shap_b64}" class="shap-img" alt="SHAP Summary Plot">' if shap_b64 else '<p>No se generó gráfico SHAP.</p>'}
                </div>
                <div class="shap-guide">
                    <h3>📖 Interpretación del Modelo</h3>
                    <p>El gráfico superior muestra los factores decisivos para la IA. Las barras <strong>rojas</strong> hacia la derecha indican características que aumentan el riesgo.</p>
                </div>
            </div>

            <!-- Critical Findings Section -->
            <h2 class="section-title">🚨 Hallazgos Críticos ({len(vulnerable_files_list)})</h2>
            
            {'' if vulnerable_files_list else '<div class="stat-card" style="margin-bottom:30px;"><h3>✅ ¡Excelente!</h3><p>No se encontraron vulnerabilidades críticas en el código analizado.</p></div>'}
    """

    # Generate Cards for Vulnerable Files
    for file_result in vulnerable_files_list:
        prob = f"{file_result.get('confidence', 0):.2%}"
        details_html = ""
        
        if file_result.get('details'):
            details = file_result['details']
            if isinstance(details.get('dangerous_calls'), list):
                for finding in details['dangerous_calls']:
                    if isinstance(finding, dict):
                        is_critical = finding['severity'] in ["Critical", "High"]
                        severity_class = "critical" if is_critical else "warning"
                        
                        details_html += f"""
                        <div class="finding-detail {severity_class}">
                            <div class="finding-header">
                                <div>
                                    <span class="finding-type">{finding['type']}</span>
                                    <span class="line-badge" style="background: #34495e; margin-left: 10px;">{finding.get('cwe', 'N/A')}</span>
                                    <span class="line-badge" style="background: #8e44ad; margin-left: 5px;">{finding.get('owasp', 'N/A')}</span>
                                </div>
                                <span class="line-badge">Línea {finding['line']}</span>
                            </div>
                            <p style="margin: 0 0 10px 0;">{finding['description']}</p>
                            <div class="code-block">{finding['content']}</div>
                            <div class="remediation-box">
                                <strong>💡 Solución:</strong> 
                                <span>{finding['remediation']}</span>
                            </div>
                        </div>
                        """
                    else:
                         details_html += f"<div class='finding-detail'>⚠️ {finding}</div>"
        
        if not details_html:
             details_html = "<div class='finding-detail' style='border-left-color: #3498db;'>🤖 <strong>Predicción ML:</strong> El modelo detectó patrones de riesgo basados en la estructura del código, aunque no hay coincidencias exactas de reglas.</div>"

        html_content += f"""
            <div class="finding-card vulnerable">
                <div class="card-header">
                    <div class="file-name">{file_result['file']}</div>
                    <div>
                        <span style="margin-right: 15px; color: #7f8c8d; font-size: 0.9em;">Confianza del Modelo: <strong>{prob}</strong></span>
                        <span class="badge badge-vuln">VULNERABLE</span>
                    </div>
                </div>
                <div class="card-body">
                    {details_html}
                </div>
            </div>
        """

    # Safe Files Section
    html_content += f"""
            <h2 class="section-title" style="color: var(--success);">✅ Archivos Seguros ({len(safe_files_list)})</h2>
            <div class="safe-table-container">
                <table class="safe-table">
                    <thead>
                        <tr>
                            <th>Archivo</th>
                            <th>Confianza</th>
                            <th>Estado</th>
                        </tr>
                    </thead>
                    <tbody>
    """
    
    for file_result in safe_files_list:
        html_content += f"""
                        <tr>
                            <td>{file_result['file']}</td>
                            <td>{file_result.get('confidence', 0):.2%}</td>
                            <td><span class="badge badge-safe">SEGURO</span></td>
                        </tr>
        """

    # Scripts for Charts
    html_content += f"""
                    </tbody>
                </table>
            </div>
        </div>

        <script>
            // Common Chart Options
            const chartOptions = {{
                responsive: true,
                plugins: {{
                    legend: {{ position: 'bottom' }}
                }}
            }};

            // Files Chart
            new Chart(document.getElementById('filesChart'), {{
                type: 'doughnut',
                data: {{
                    labels: ['Vulnerables', 'Seguros'],
                    datasets: [{{
                        data: [{len(vulnerable_files_list)}, {len(safe_files_list)}],
                        backgroundColor: ['#e74c3c', '#27ae60'],
                        borderWidth: 0
                    }}]
                }},
                options: chartOptions
            }});

            // Vulnerabilities Chart
            new Chart(document.getElementById('vulnChart'), {{
                type: 'bar',
                data: {{
                    labels: {json.dumps(vuln_labels)},
                    datasets: [{{
                        label: 'Cantidad de Hallazgos',
                        data: {json.dumps(vuln_counts)},
                        backgroundColor: '#3498db',
                        borderRadius: 5
                    }}]
                }},
                options: {{
                    ...chartOptions,
                    scales: {{
                        y: {{ beginAtZero: true, ticks: {{ stepSize: 1 }}, grid: {{ color: '#f0f0f0' }} }},
                        x: {{ grid: {{ display: false }} }}
                    }}
                }}
            }});
        </script>
    </body>
    </html>
    """

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    print(f"Report generated successfully: {output_file}")

if __name__ == "__main__":
    generate_html_report()
