# Desarrollo de Software Seguro: Pipeline CI/CD DevSecOps con IA

**Autor:** Axel Lenin Pullaguari Cedeño  
**Materia:** Desarrollo de Software Seguro  
**Universidad:** Universidad de las Fuerzas Armadas ESPE  
**Enlace al Proyecto:** [GitHub](https://github.com/ALPullaguariSW/ProyectoMineriaDatos)

---

## 📋 Descripción del Proyecto

Este proyecto implementa una infraestructura **DevSecOps** completa que integra un pipeline CI/CD seguro y automatizado con un modelo de **Inteligencia Artificial** (basado en Minería de Datos) para la detección proactiva de vulnerabilidades en el código fuente.

El sistema garantiza que **solo el código seguro llegue a producción**, cumpliendo con los principios de *Shift-Left Security*.

### 🌟 Características Clave
1.  **Modelo de IA Propio**: Random Forest entrenado con +180,000 archivos reales para detectar patrones inseguros (OWASP Top 10).
2.  **Pipeline Bloqueante**: GitHub Actions impide el merge de código vulnerable.
3.  **API REST de Escaneo**: Servicio FastAPI (`src/app.py`) para análisis bajo demanda.
4.  **Despliegue Automático**: Contenedores Docker desplegados automáticamente en Render.
5.  **Notificaciones en Tiempo Real**: Alertas vía Telegram (Inicio, Fallo de Seguridad, Merge, Despliegue).

---

## 🛠️ Arquitectura del Pipeline

El flujo de trabajo sigue una estricta lógica de ramas para asegurar la calidad:

```mermaid
graph LR
    A[Dev Push] -->|Pull Request| B(Rama 'test')
    B --> C{🤖 Escaneo de Seguridad con IA}
    C -->|VULNERABLE| D[❌ Bloqueo & Notificación Telegram]
    D --> E[Etiqueta 'fixing-required']
    C -->|SEGURO| F[✅ Merge a 'test']
    F --> G{🧪 Pruebas Unitarias}
    G -->|FALLO| H[❌ Detener Pipeline]
    G -->|ÉXITO| I[🚀 Merge a 'main' & Despliegue (Docker)]
```

---

## 🚀 Instalación y Uso Local

### Prerrequisitos
*   Python 3.9+
*   Docker (Opcional, para despliegue)

### 1. Configuración
```bash
git clone https://github.com/ALPullaguariSW/ProyectoMineriaDatos
cd ProyectoMineriaDatos
pip install -r requirements.txt
```

### 2. Escaneo de Vulnerabilidades (CLI)
Para analizar un archivo o directorio localmente:
```bash
# Escanear todo el directorio fuente
python src/model/predict.py src/

# Escanear un repositorio externo (clona y analiza)
python src/assess/scan_repo.py https://github.com/OWASP/NodeGoat
```

### 3. Ejecutar la API (FastAPI)
Levanta el servidor de escaneo localmente:
```bash
uvicorn src.app:app --reload
```
Accede a la documentación interactiva en: `http://localhost:8000/docs`

### 4. Ejecutar con Docker
```bash
docker build -t secure-scanner .
docker run -p 8000:8000 secure-scanner
```

---

## ⚙️ Configuración del Pipeline (GitHub Actions)

Para que el pipeline funcione en tu fork, configura los siguientes **GitHub Secrets**:

| Secreto | Descripción |
| :--- | :--- |
| `TELEGRAM_TOKEN` | Token de tu bot de Telegram (BotFather) |
| `TELEGRAM_CHAT_ID` | Tu ID de chat (userinfo bot) |

---

## 📂 Estructura del Proyecto

```
ProyectoMineriaDatos/
├── .github/workflows/      # security_scan.yml (Lógica del Pipeline)
├── data/                   # Datasets masivos (+1.5GB, ignorados en git)
├── models/                 # rf_model.pkl (Cerebro de la IA)
├── PullaguariAxel_InformeLaboratorio/ # Informe Técnico PDF
├── src/
│   ├── app.py              # API Backend (FastAPI)
│   ├── assess/             # Notificaciones, Reportes HTML, Escáner de Repos
│   ├── model/              # Lógica de Predicción y Entrenamiento
│   └── sample/             # Minería de Datos (Repo Miner)
├── Dockerfile              # Configuración de Contenedor
├── render.yaml             # Despliegue en la Nube
├── requirements.txt        # Dependencias (scikit-learn, fastapi, etc.)
└── README.md               # Documentación
```

## 📊 Rendimiento del Modelo
*   **Algoritmo**: Random Forest Classifier
*   **Accuracy**: 99.9% (Validación Cruzada)
*   **Features**: TF-IDF (N-grams), Complejidad Ciclomática, Profundidad AST, Llamadas Peligrosas.

---
**Nota**: Este proyecto fue desarrollado como parte del Proyecto Integrador Parcial II. Prohibido el uso de LLMs generativos integrada en el núcleo de detección.

---

## 🔗 Enlaces Importantes de Entrega

| Recurso | Enlace | Estado |
| :--- | :--- | :--- |
| **Repositorio GitHub** | [ALPullaguariSW/ProyectoMineriaDatos](https://github.com/ALPullaguariSW/ProyectoMineriaDatos) | ✅ Público |
| **Informe Técnico** | [Ver PDF](PullaguariAxel_InformeLaboratorio/PullaguariAxel_InformeLaboratorio.pdf) | ✅ Completo |
| **Despliegue (Render)** | [https://proyectomineriadatos.onrender.com](https://proyectomineriadatos.onrender.com) | ⏳ *Requiere Config* |
| **Bot de Telegram** | [@TuBotName_Bot](https://t.me/TuBotName_Bot) | ✅ Activo |
| **Video Demostrativo** | *Pendiente de carga* | 📹 |
