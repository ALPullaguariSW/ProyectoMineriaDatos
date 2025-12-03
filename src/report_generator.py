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
    except FileNotFoundError:
        print("No scan results found. Skipping report.")
        return

    # Load SHAP Image as Base64
    shap_b64 = ""
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
            # Count types
            if res.get('details') and isinstance(res['details'].get('dangerous_calls'), list):
                for finding in res['details']['dangerous_calls']:
                    if isinstance(finding, dict):
                        v_type = finding['type']
                        vuln_types[v_type] = vuln_types.get(v_type, 0) + 1
                    else:
                        # Fallback for old string format
                        vuln_types['Generic Risk'] = vuln_types.get('Generic Risk', 0) + 1
            else:
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
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f4f4f9; color: #333; }}
            header {{ background-color: #2c3e50; color: white; padding: 20px; text-align: center; }}
            .container {{ max-width: 1200px; margin: 20px auto; padding: 20px; }}
            .card {{ background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
            h1, h2, h3 {{ color: #2c3e50; }}
            .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }}
            .stat-box {{ text-align: center; padding: 20px; background: #ecf0f1; border-radius: 8px; }}
            .stat-number {{ font-size: 2em; font-weight: bold; color: #e74c3c; }}
            .stat-label {{ color: #7f8c8d; }}
            .safe {{ color: #27ae60; }}
            .vuln-table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            .vuln-table th, .vuln-table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            .vuln-table th {{ background-color: #34495e; color: white; }}
            .vuln-row:hover {{ background-color: #f1f1f1; }}
            .badge {{ padding: 5px 10px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }}
            .badge-high {{ background-color: #e74c3c; color: white; }}
            .badge-safe {{ background-color: #27ae60; color: white; }}
            .detail-list {{ list-style-type: none; padding: 0; }}
            .detail-item {{ background: #fff3cd; padding: 5px; margin: 2px 0; border-left: 4px solid #ffc107; font-size: 0.9em; }}
            .shap-container {{ text-align: center; margin-top: 20px; }}
            .shap-img {{ max-width: 100%; border: 1px solid #ddd; border-radius: 4px; }}
            footer {{ text-align: center; padding: 20px; color: #7f8c8d; font-size: 0.9em; }}
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
            <h2 class="section-title" style="color: #c0392b;">🚨 Hallazgos Críticos ({len(vulnerable_files_list)})</h2>
            
            {'' if vulnerable_files_list else '<p style="text-align:center; padding:20px; background:white; border-radius:8px;">✅ ¡Felicidades! No se encontraron vulnerabilidades críticas.</p>'}
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
                        severity_color = "#e74c3c" if finding['severity'] in ["Critical", "High"] else "#f39c12"
                        details_html += f"""
                        <div style="border-left: 4px solid {severity_color}; background: #fcfcfc; padding: 15px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #eee;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                                <strong style="color: {severity_color};">{finding['type']}</strong>
                                <span style="background: #34495e; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8em;">Línea {finding['line']}</span>
                            </div>
                            <p style="margin: 5px 0; color: #555; font-size: 0.95em;">{finding['description']}</p>
                            <div style="background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 4px; font-family: monospace; margin: 10px 0; font-size: 0.9em; overflow-x: auto;">
                                {finding['content']}
                            </div>
                            <div style="margin-top: 8px; color: #27ae60; font-size: 0.9em; font-weight: 600;">
                                💡 {finding['remediation']}
                            </div>
                        </div>
                        """
                    else:
                         details_html += f"<div>⚠️ {finding}</div>"
        
        if not details_html:
             details_html = "<div style='padding:15px; background:#e8f4f8; color:#2980b9; border-radius:4px;'>🤖 Riesgo detectado por predicción ML (Patrón complejo).</div>"

        html_content += f"""
            <div class="finding-card vulnerable">
                <div class="card-header">
                    <div class="file-name">{file_result['file']}</div>
                    <div>
                        <span style="margin-right: 15px; color: #7f8c8d; font-size: 0.9em;">Riesgo: <strong>{prob}</strong></span>
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
            <h2 class="section-title" style="color: #27ae60;">✅ Archivos Seguros ({len(safe_files_list)})</h2>
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

        <script>
            // Files Chart
            new Chart(document.getElementById('filesChart'), {{
                type: 'doughnut',
                data: {{
                    labels: ['Vulnerables', 'Seguros'],
                    datasets: [{{
                        data: [{len(vulnerable_files_list)}, {len(safe_files_list)}],
                        backgroundColor: ['#e74c3c', '#27ae60']
                    }}]
                }}
            }});

            // Vulnerabilities Chart
            new Chart(document.getElementById('vulnChart'), {{
                type: 'bar',
                data: {{
                    labels: {json.dumps(vuln_labels)},
                    datasets: [{{
                        label: 'Cantidad',
                        data: {json.dumps(vuln_counts)},
                        backgroundColor: '#3498db'
                    }}]
                }},
                options: {{
                    responsive: true,
                    scales: {{
                        y: {{ beginAtZero: true, ticks: {{ stepSize: 1 }} }}
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
