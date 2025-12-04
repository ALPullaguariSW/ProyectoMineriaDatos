# Detección de Vulnerabilidades de Software mediante Minería de Datos (SEMMA)

**Autor:** Axel Lenin Pullaguari Cedeño  
**Materia:** Desarrollo de Software Seguro  
**Universidad:** Universidad de las Fuerzas Armadas ESPE

---

## 📋 Descripción del Proyecto

Este proyecto implementa un sistema automatizado para la detección de vulnerabilidades en código fuente utilizando técnicas de **Minería de Datos** y **Machine Learning**, siguiendo rigurosamente la metodología **SEMMA** (Sample, Explore, Modify, Model, Assess).

El sistema es capaz de:
1.  **Minar Repositorios**: Descargar y analizar miles de archivos de proyectos reales (GitHub).
2.  **Aprender Patrones**: Entrenar modelos (Random Forest) para distinguir entre código seguro y vulnerable.
3.  **Escanear**: Analizar nuevos archivos en busca de riesgos de seguridad (OWASP Top 10).
4.  **Integrarse**: Funcionar dentro de un pipeline CI/CD (GitHub Actions).

## 🚀 Instalación y Requisitos

### Prerrequisitos
*   Python 3.8+
*   Git

### Configuración del Entorno
1.  Clonar el repositorio:
    ```bash
    git clone <url-del-repositorio>
    cd ProyectoMineriaDatos
    ```

2.  Crear y activar un entorno virtual:
    ```bash
    python -m venv venv
    # Windows
    .\venv\Scripts\activate
    # Linux/Mac
    source venv/bin/activate
    ```

3.  Instalar dependencias:
    ```bash
    pip install -r requirements.txt
    ```

---

## ⚙️ Uso del Proyecto

El proyecto está modularizado según las fases de SEMMA. Puedes ejecutar el pipeline completo o fases individuales.

### 1. Fase Sample (Minería de Datos)
Para generar el dataset masivo desde cero (esto tomará tiempo):
```bash
python src/sample/repo_miner.py
```
*   **Output**: `data/mined_dataset.csv` (Dataset con ~180k muestras).

### 2. Fase Modify & Model (Entrenamiento)
Para preprocesar los datos y entrenar el modelo:
```bash
python src/model/train_model.py
```
*   **Output**: 
    *   `models/rf_model.pkl` (Modelo entrenado).
    *   `reports/learning_curve.png` (Gráfico de rendimiento).

### 3. Fase Assess (Escaneo de Vulnerabilidades)
Para escanear un directorio o archivo específico en busca de vulnerabilidades:
```bash
python src/assess/scan_repo.py
```
*   **Nota**: Configura el directorio objetivo en el script o pásalo como argumento (si está implementado).
*   **Output**: `reports/scan_results.html` (Reporte visual).

---

## 📂 Estructura del Proyecto

```
ProyectoMineriaDatos/
├── .github/workflows/      # Pipeline CI/CD (GitHub Actions)
├── data/                   # Datasets (Ignorados en git por tamaño)
├── models/                 # Modelos serializados (.pkl)
├── PullaguariAxel_InformeLaboratorio/ # Informe Técnico (LaTeX + PDF)
├── reports/                # Gráficos y reportes generados
├── src/
│   ├── assess/             # Fase Assess (Reportes, Escaneo)
│   ├── model/              # Fase Model (Entrenamiento, Predicción)
│   ├── modify/             # Fase Modify (Preprocesamiento)
│   └── sample/             # Fase Sample (Minería, Carga de Datos)
├── tests/                  # Pruebas Unitarias
├── requirements.txt        # Dependencias
└── README.md               # Este archivo
```

## 📊 Resultados Obtenidos

*   **Precisión del Modelo**: 99.9%
*   **Datos Procesados**: +180,000 archivos.
*   **Lenguajes Soportados**: C, C++, Python, Java, JS, TS, Go, Ruby, C#, Swift.

---

## 📄 Informe Técnico
El informe completo del laboratorio, incluyendo la metodología detallada y el análisis de resultados, se encuentra en la carpeta:
`PullaguariAxel_InformeLaboratorio/main.pdf`
