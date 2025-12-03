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
                <p>Este gráfico muestra qué características (palabras clave, métricas) influyeron más en las decisiones del modelo.</p>
                
                <div class="shap-container">
                    {f'<img src="data:image/png;base64,{shap_b64}" class="shap-img" alt="SHAP Summary Plot">' if shap_b64 else '<p>No se generó gráfico SHAP.</p>'}
                </div>

                <div class="shap-guide">
                    <h3>📖 Guía de Interpretación Técnica</h3>
                    <p>Este gráfico de <strong>SHAP (SHapley Additive exPlanations)</strong> desglosa la predicción del modelo:</p>
                    <ul>
                        <li><strong>Eje Y (Características):</strong> Las variables más importantes están arriba. Si ves palabras como <code>eval</code>, <code>exec</code> o <code>complexity</code> arriba, significa que son los factores decisivos.</li>
                        <li><strong>Eje X (Valor SHAP):</strong> Indica el impacto en la predicción.
                            <ul>
                                <li>➡️ <strong>Derecha (Positivo):</strong> Empuja la predicción hacia <strong>VULNERABLE (Clase 1)</strong>.</li>
                                <li>⬅️ <strong>Izquierda (Negativo):</strong> Empuja la predicción hacia <strong>SEGURO (Clase 0)</strong>.</li>
                            </ul>
                        </li>
                        <li><strong>Color (Valor de la Característica):</strong>
                            <ul>
                                <li>🔴 <strong>Rojo (Alto):</strong> Un valor alto de esta característica (ej: alta complejidad) causa el impacto.</li>
                                <li>🔵 <strong>Azul (Bajo):</strong> La ausencia o valor bajo de esta característica causa el impacto.</li>
                            </ul>
                        </li>
                    </ul>
                    <p><em>Ejemplo:</em> Si ves una barra roja larga hacia la derecha para la característica <code>complexity</code>, significa que la <strong>alta complejidad</strong> del código está aumentando drásticamente el riesgo de vulnerabilidad.</p>
                </div>
            </div>

            <!-- Detailed Findings -->
            <div class="card" style="background: transparent; box-shadow: none;">
                <h2>🔍 Hallazgos Detallados</h2>
                <!-- Cards Loop -->
    """

    # Add Cards
    for file_result in results.get("results", []):
        is_vuln = file_result.get('status') == 'VULNERABLE'
        status_class = "vulnerable" if is_vuln else "safe"
        badge_class = "badge-high" if is_vuln else "badge-safe"
        status_text = file_result.get('status', 'UNKNOWN')
        prob = f"{file_result.get('confidence', 0):.2%}"
        
        details_html = ""
        if file_result.get('details'):
            details = file_result['details']
            
            # New Rich Findings (List of Dicts)
            if isinstance(details.get('dangerous_calls'), list) and len(details['dangerous_calls']) > 0:
                first_item = details['dangerous_calls'][0]
                if isinstance(first_item, dict):
                    details_html += "<div style='margin-top: 15px;'>"
                    for finding in details['dangerous_calls']:
                        severity_color = "#e74c3c" if finding['severity'] in ["Critical", "High"] else "#f39c12"
                        details_html += f"""
                        <div style="border-left: 4px solid {severity_color}; background: #fff; padding: 15px; margin-bottom: 15px; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                                <strong style="color: {severity_color}; font-size: 1.1em;">{finding['type']} <span style="font-size:0.8em; opacity:0.8;">({finding['severity']})</span></strong>
                                <span style="background: #34495e; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.9em;">Línea {finding['line']}</span>
                            </div>
                            <p style="margin: 5px 0; color: #555;">{finding['description']}</p>
                            <div style="background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 4px; font-family: 'Consolas', monospace; margin: 10px 0; overflow-x: auto;">
                                {finding['content']}
                            </div>
                            <div style="background: #e8f8f5; color: #16a085; padding: 10px; border-radius: 4px; font-size: 0.95em; border: 1px solid #d1f2eb;">
                                <strong>💡 Solución:</strong> {finding['remediation']}
                            </div>
                        </div>
                        """
                    details_html += "</div>"
                else:
                    for call in details['dangerous_calls']:
                        details_html += f"<div style='padding:5px;'>⚠️ {call}</div>"
            
            # Complexity
            if details.get('complexity', 0) > 10:
                details_html += f"<div style='margin-top:10px; padding:10px; background:#fff3cd; color:#856404; border-radius:4px;'>📉 <strong>Complejidad Ciclomática Alta:</strong> {details['complexity']} (Difícil de mantener)</div>"
            # AST Depth
            if details.get('ast_depth', 0) > 5:
                details_html += f"<div style='margin-top:5px; padding:10px; background:#fff3cd; color:#856404; border-radius:4px;'>🌳 <strong>Profundidad de AST excesiva:</strong> {details['ast_depth']}</div>"
        
        if not details_html and is_vuln:
             details_html = "<div style='padding:15px; background:#e8f4f8; color:#2980b9; border-radius:4px;'>🤖 El modelo detectó patrones de riesgo basados en el texto del código (ML Prediction).</div>"

        html_content += f"""
            <div class="finding-card {status_class}">
                <div class="card-header">
                    <div class="card-title">{file_result['file']}</div>
                    <div>
                        <span style="margin-right: 10px; color: #7f8c8d;">Confianza: <strong>{prob}</strong></span>
                        <span class="badge {badge_class}">{status_text}</span>
                    </div>
                </div>
                <div class="card-body">
                    {details_html if details_html else "<p style='color:#7f8c8d; font-style:italic;'>No se detectaron problemas específicos.</p>"}
                </div>
            </div>
        """

    html_content += """
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
