# Desarrollo de Software Seguro: Pipeline CI/CD con Minería de Datos

**Universidad de las Fuerzas Armadas ESPE**  
**Departamento de Ciencias de la Computación**  
**Carrera de Ingeniería en Software**  
**Proyecto Integrador Parcial II**

Este repositorio contiene la implementación de un pipeline CI/CD seguro que integra un modelo de Inteligencia Artificial (Minería de Datos) para la detección automática de vulnerabilidades en código fuente.

## 1. Descripción del Proyecto

El sistema analiza código fuente (C/C++, Python, Java) utilizando un modelo de clasificación (Random Forest/SVM) entrenado con técnicas de minería de datos (SEMMA). Si detecta vulnerabilidades, bloquea el pipeline, notifica al desarrollador vía Telegram y genera un reporte.

**Características Principales:**
*   **Modelo Propio**: Entrenado con datasets públicos (ZeoVan MSR_20) y sintéticos (OWASP Top 10).
*   **No LLMs**: Uso exclusivo de algoritmos clásicos (Random Forest, SVM) y features explícitos (TF-IDF, AST Depth, Dangerous Calls).
*   **Pipeline 3 Etapas**: Security Scan -> Unit Tests -> Deploy.
*   **Notificaciones**: Alertas en tiempo real vía Telegram.
*   **Despliegue**: API REST (FastAPI) dockerizada lista para producción (Render/Railway).

## 2. Instrucciones de Setup

### Requisitos Previos
*   Python 3.9+
*   Docker (opcional, para despliegue local)
*   Cuenta en Telegram (para el bot)

### Instalación Local
1.  Clonar el repositorio:
    ```bash
    git clone https://github.com/ALPullaguariSW/ProyectoMineriaDatos.git
    cd ProyectoMineriaDatos
    ```
2.  Instalar dependencias:
    ```bash
    pip install -r requirements.txt
    ```
3.  Entrenar el modelo (si no existen los archivos .pkl):
    ```bash
    python src/data_loader.py
    python src/train_model.py
    ```

### Ejecución del Escáner (Modo Linter)
Para escanear un directorio en busca de vulnerabilidades:
```bash
python src/predict.py src/
```
Esto generará un reporte `scan_report.json`.

### Ejecución de la API
Para levantar el servidor de predicción localmente:
```bash
uvicorn src.app:app --reload
```
Acceder a `http://localhost:8000/docs` para probar el endpoint `/scan`.

## 3. Entrenamiento del Modelo

El modelo sigue la metodología **SEMMA**:
1.  **Sample**: `src/data_loader.py` descarga datos de GitHub y genera sintéticos.
2.  **Explore**: `src/eda.py` analiza la distribución de clases.
3.  **Modify**: `src/preprocessing.py` extrae features:
    *   **TF-IDF** (Texto)
    *   **Complejidad Ciclomática** (Métrica)
    *   **Profundidad AST** (Métrica Estructural)
    *   **Llamadas Peligrosas** (Patrones Regex: `exec`, `system`, etc.)
4.  **Model**: `src/train_model.py` entrena Random Forest y SVM con **GridSearchCV**.
5.  **Assess**: `src/evaluate.py` genera métricas (Accuracy > 82%).

## 4. Configuración del Pipeline CI/CD

El archivo `.github/workflows/security_scan.yml` define el flujo:

1.  **Trigger**: Pull Request a `test` o `main`.
2.  **Etapa 1: Security Scan**:
    *   Ejecuta `src/predict.py`.
    *   Si detecta vulnerabilidad -> **Falla el Job** y envía alerta a Telegram.
3.  **Etapa 2: Unit Tests**:
    *   Ejecuta `pytest`.
4.  **Etapa 3: Deploy**:
    *   Simula despliegue a producción (solo en `main`).

### Secretos de GitHub
Configurar los siguientes secretos en el repositorio:
*   `TELEGRAM_TOKEN`: Token del bot de Telegram.
*   `TELEGRAM_CHAT_ID`: ID del chat donde llegarán las alertas.

## 5. Evidencias

### Bot de Telegram
El sistema envía notificaciones en cada etapa:
*   🚀 Pipeline Started
*   ❌ Security Alert / ✅ Security Scan Passed
*   🚀 Deployment Successful

### Despliegue en Producción
La API está contenerizada en `Dockerfile` y lista para desplegarse en servicios como Render o Railway.

---
**Autor**: [Tu Nombre]
**Fecha**: Diciembre 2025
