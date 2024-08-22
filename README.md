# Aplicación de Firewall

Este script de Python implementa una aplicación de firewall básica utilizando la biblioteca `tkinter` para la interfaz gráfica y el manejo de direcciones IP.

## Uso

1. Asegúrate de tener Python instalado en tu sistema.
2. Ejecuta el script con el siguiente comando en tu terminal:

    ```bash
    python firewall_app.py
    ```

3. Se abrirá la ventana de la interfaz gráfica con campos para la dirección IP de origen, la dirección IP de destino y el protocolo, junto con un botón "Check Firewall".
4. Ingresa la dirección IP de origen y destino deseada, y selecciona el protocolo.
5. Haz clic en el botón "Check Firewall" para ver la acción del firewall basada en las reglas predefinidas.

## Dependencias

- Python 3.x
- Biblioteca `tkinter`

## Estructura del Código

- `Packet`: Representa un paquete de red con validación de dirección IP de origen, dirección IP de destino y protocolo.
- `PacketFilterRule`: Define reglas de filtrado para paquetes basadas en direcciones IP de origen, direcciones IP de destino, protocolos y acción (ALLOW o DENY).
- `Firewall`: Gestiona una colección de reglas de filtrado de paquetes y procesa los paquetes entrantes en consecuencia.
- `FirewallApp`: Aplicación de interfaz gráfica utilizando `tkinter` para interactuar con el firewall.

## Licencia

Este proyecto está bajo la [Licencia MIT](LICENSE).
## Cambios Realizados

### 1. Formato de los logs
- Se añadió un formato más detallado para los logs, incluyendo fecha, hora, nivel de log, y mensaje:
  ```python
  logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')
### 2. Nombres de constantes
- Se actualizó el nombre de la constante valid_protocols a VALID_PROTOCOLS en la clase Packet para seguir la convención de nombres de constantes en mayúsculas.
- 3. Uso de métodos estáticos y de clase
validate_ip en la clase Packet se convirtió en un método estático (@staticmethod).
validate_protocol en la clase Packet se convirtió en un método de clase (@classmethod).
- Los métodos de validación
```python
(validate_ips, validate_protocols, validate_action) en la clase PacketFilterRule se convirtieron en métodos estáticos (@staticmethod).
```
### 4. Estilo y presentación de la GUI
- Se añadió una fuente y estilo consistente para los widgets de la GUI:
```python
style = {"fg": "white", "bg": "black", "font": ("Arial", 10, "bold")}
```
### 5. Refactorización de la creación de widgets Entry
- Se creó un método auxiliar create_labeled_entry para reducir duplicación y mejorar la organización del código:
```python
def create_labeled_entry(self, label_text, default_text, style):
    ...
```
### 6. Acceso dinámico a valores de Entry widgets
- Se implementó un acceso más dinámico a los valores de los Entry widgets usando winfo_children():
```python
source_ip = self.source_frame.winfo_children()[1].get()
destination_ip = self.destination_frame.winfo_children()[1].get()
```
# Acepto sugerencias para seguir mejorando el proyecto :D
