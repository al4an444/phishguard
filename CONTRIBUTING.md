# Contribuir a PhishGuard

## Preparar el entorno

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev,api]"
pytest
ruff check .
```

## Añadir o cambiar una regla

1. Escribe la regla en `src/phishguard/rules.py` con el decorador `@rule`. Debe devolver `Finding`s con
   un mensaje que explique la señal en lenguaje claro y la evidencia concreta.
2. Añade tests en `tests/test_rules.py`: al menos una URL que la active y una URL legítima que **no**
   la active.
3. Ejecuta `python scripts/evaluate.py data/sample.csv --show-errors` y comprueba que la precisión no empeora.
4. Documenta la regla y su peso en la tabla del README.

## Reglas del proyecto

- El análisis **nunca** hace peticiones de red ni visita las URLs.
- Todo lo que viene de una URL o un correo analizado es entrada no confiable: en la interfaz web se
  inserta solo con `textContent`, nunca como HTML (hay un test que lo comprueba).
- El modelo se distribuye como JSON. No se aceptan modelos en pickle.

## Reportar errores de detección

Usa la plantilla *Falso positivo / falso negativo* y desactiva las URLs maliciosas
(`hxxp://`, `ejemplo[.]com`). Las vulnerabilidades se reportan en privado, ver [SECURITY.md](SECURITY.md).
