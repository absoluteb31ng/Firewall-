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
