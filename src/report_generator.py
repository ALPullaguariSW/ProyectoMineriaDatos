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
            <h1>🛡️ Reporte de Análisis de Seguridad (SEMMA)</h1>
            <p>Generado automáticamente por el Pipeline de Minería de Datos</p>
        </header>

        <div class="container">
            <!-- Executive Summary -->
            <div class="card">
                <h2>📊 Resumen Ejecutivo</h2>
                <div class="stats-grid">
                    <div class="stat-box">
                        <div class="stat-number">{total_files}</div>
                        <div class="stat-label">Archivos Escaneados</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number" style="color: {'#e74c3c' if vulnerable_files > 0 else '#27ae60'}">{vulnerable_files}</div>
                        <div class="stat-label">Archivos Vulnerables</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number safe">{safe_files}</div>
                        <div class="stat-label">Archivos Seguros</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number" style="color: #3498db">{scan_duration}s</div>
                        <div class="stat-label">Tiempo de Escaneo</div>
                    </div>
                </div>
            </div>

            <!-- Explainability Section -->
            <div class="card">
                <h2>🧠 Explicabilidad del Modelo (XAI)</h2>
                <p>Este gráfico muestra qué características (palabras clave, métricas) influyeron más en las decisiones del modelo. 
                Basado en <strong>SHAP (SHapley Additive exPlanations)</strong>.</p>
                <div class="shap-container">
                    {f'<img src="data:image/png;base64,{shap_b64}" class="shap-img" alt="SHAP Summary Plot">' if shap_b64 else '<p>No se generó gráfico SHAP.</p>'}
                </div>
            </div>

            <!-- Detailed Findings -->
            <div class="card">
                <h2>🔍 Hallazgos Detallados</h2>
                <table class="vuln-table">
                    <thead>
                        <tr>
                            <th>Archivo</th>
                            <th>Estado</th>
                            <th>Probabilidad de Riesgo</th>
                            <th>Detalles Técnicos y Recomendaciones</th>
                        </tr>
                    </thead>
                    <tbody>
    """

    # Add rows
    for file_result in results.get("results", []):
        is_vuln = file_result.get('status') == 'VULNERABLE'
        status_class = "badge-high" if is_vuln else "badge-safe"
        status_text = file_result.get('status', 'UNKNOWN')
        prob = f"{file_result.get('confidence', 0):.2%}"
        
        details_html = ""
        if file_result.get('details'):
            details = file_result['details']
            # Dangerous Calls
            if details.get('dangerous_calls'):
                for call in details['dangerous_calls']:
                    details_html += f"<li class='detail-item'>⚠️ {call}</li>"
            # Complexity
            if details.get('complexity', 0) > 10:
                details_html += f"<li class='detail-item'>📉 Complejidad Ciclomática Alta: {details['complexity']} (Difícil de mantener)</li>"
            # AST Depth
            if details.get('ast_depth', 0) > 5:
                details_html += f"<li class='detail-item'>🌳 Profundidad de AST excesiva: {details['ast_depth']}</li>"
        
        if not details_html and is_vuln:
             details_html = "<li class='detail-item'>🤖 El modelo detectó patrones de riesgo basados en el texto del código.</li>"

        html_content += f"""
                        <tr class="vuln-row">
                            <td>{file_result['file']}</td>
                            <td><span class="badge {status_class}">{status_text}</span></td>
                            <td>{prob}</td>
                            <td><ul class="detail-list">{details_html}</ul></td>
                        </tr>
        """

    html_content += """
                    </tbody>
                </table>
            </div>
        </div>

        <footer>
            Reporte generado el """ + timestamp + """ | Proyecto de Minería de Datos - ESPE
        </footer>
    </body>
    </html>
    """

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    print(f"Report generated successfully: {output_file}")

if __name__ == "__main__":
    generate_html_report()
