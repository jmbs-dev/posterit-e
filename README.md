# Posterit-E: Backend Serverless

![alt text](https://img.shields.io/badge/build-passing-brightgreen)
![alt text](https://img.shields.io/badge/License-MIT-yellow.svg)

Repositorio oficial para el backend serverless del proyecto Posterit-E, una plataforma de legado digital segura, privada y de código abierto.

---

## 📜 Resumen del Proyecto

Posterit-E es una plataforma diseñada para permitir a los usuarios almacenar información confidencial (como contraseñas, claves de criptomonedas, documentos o notas personales) y garantizar su entrega controlada a beneficiarios designados tras un evento que incapacite al titular, como el fallecimiento.

El sistema se fundamenta en un principio de confianza mínima, donde la plataforma nunca tiene acceso al contenido de los secretos del usuario.

---

## ✨ Principios Fundamentales

- 🔐 **Seguridad Zero-Knowledge (Conocimiento Cero):** El diseño criptográfico garantiza que el servidor actúa como un "custodio ciego". Todas las operaciones de cifrado y descifrado ocurren exclusivamente en el lado del cliente (en el navegador del titular y del beneficiario). El servidor solo almacena y gestiona "blobs" de datos cifrados.
- 🛡️ **Cifrado End-to-End (E2E):** La información viaja y se almacena siempre cifrada. Solo el titular (al crear el secreto) y el beneficiario final (al recuperarlo con la contraseña correcta) pueden acceder al contenido en texto plano.
- 🚀 **Arquitectura Serverless en AWS:** Para garantizar escalabilidad, eficiencia en costos y un enfoque en la lógica de negocio, el backend está construido 100% con servicios gestionados de AWS, principalmente AWS Lambda, API Gateway, DynamoDB y S3.
- 🌐 **Código Abierto (Open Source):** La transparencia es clave para la confianza. Al ser de código abierto, el proyecto permite la auditoría pública e independiente de su código y protocolos de seguridad.

---

## 🏛️ Arquitectura del Backend

Este repositorio contiene el código fuente y la configuración de infraestructura como código (IaC) para todas las funciones del backend. Utilizamos el **AWS Serverless Application Model (SAM)** para definir y desplegar los recursos.

El "cerebro" de la arquitectura se encuentra en el archivo `template.yaml`, que define:

- **API Gateway:** Los endpoints RESTful que exponen la funcionalidad.
- **AWS Lambda:** Las funciones que contienen la lógica de negocio.
- **DynamoDB:** La tabla NoSQL para almacenar metadatos y estados.
- **S3:** El bucket para almacenar los secretos cifrados.
- **Roles y Permisos IAM:** Las políticas que aseguran la comunicación entre servicios bajo el principio de mínimo privilegio.

---

## 📁 Estructura del Repositorio

El proyecto sigue una estructura de monorepo, donde cada función Lambda reside en su propio directorio para aislar sus dependencias y facilitar su gestión.

```text
posterit-e-lambdas/
├── functions/
│   ├── store_secret_lambda/
│   │   ├── app.py             # Lógica de la función
│   │   └── requirements.txt   # Dependencias de Python
│   ├── activation_lambda/
│   │   ├── app.py
│   │   └── requirements.txt
│   ├── cancellation_lambda/
│   │   ├── app.py
│   │   └── requirements.txt
│   └── release_lambda/
│       ├── app.py
│       └── requirements.txt
│
├── template.yaml              # Plantilla de AWS SAM (Infraestructura como Código)
└── README.md                  # Este archivo
```

---

## 🚀 Empezar a Desarrollar

Sigue estos pasos para configurar tu entorno de desarrollo y desplegar el backend en tu propia cuenta de AWS.

### Prerrequisitos

- Una cuenta de AWS.
- Python 3.9 o superior.
- AWS CLI configurado con tus credenciales.
- AWS SAM CLI instalado.

### Construcción

El comando `sam build` compila el código fuente, descarga las dependencias de cada función Lambda y prepara los artefactos para el despliegue.

```bash
# Desde el directorio raíz del proyecto
sam build
```

### Despliegue

El comando `sam deploy --guided` empaqueta y despliega la infraestructura definida en `template.yaml`. Si es la primera vez que despliegas, o si quieres personalizar los recursos, puedes pasar los parámetros requeridos:

Primero, exporta el ARN de tu identidad verificada en SES como una variable de entorno (esto evita exponerlo en el repositorio):

```bash
export SES_IDENTITY_ARN=arn:aws:ses:REGION:CUENTA:identity/tu-dominio-o-email.com
```

Luego ejecuta el despliegue usando la variable:

```bash
sam deploy --guided \
  --parameter-overrides \
  PosteritETableName=PosteritETable \
  PosteritES3BucketName=posterite \
  SESIdentityArn=$SES_IDENTITY_ARN
```

- `PosteritETableName`: Nombre de la tabla DynamoDB para los secretos.
- `PosteritES3BucketName`: Nombre del bucket S3 para los secretos cifrados.
- `SESIdentityArn`: ARN de la identidad verificada en SES para envío de emails (puede ser un dominio o email).

Sigue las instrucciones en pantalla para completar el despliegue. Para despliegues posteriores, puedes ejecutar simplemente `sam deploy`.

---

## 🤝 Cómo Contribuir

¡Las contribuciones son bienvenidas! Si deseas mejorar Posterit-E, por favor sigue estos pasos:

1. Haz un **Fork** de este repositorio.
2. Crea una nueva rama para tu funcionalidad:
   ```bash
   git checkout -b feature/nueva-funcionalidad
   ```
3. Haz tus cambios y realiza commits atómicos.
4. Haz un **Push** a tu rama:
   ```bash
   git push origin feature/nueva-funcionalidad
   ```
5. Abre un **Pull Request** hacia la rama `main` del repositorio original.

---

## 🤖 Contexto para Agentes de IA

Este es un resumen estructurado para que los agentes de IA y los LLMs comprendan el proyecto rápidamente.

- **Objetivo Principal:** Implementar el backend de un sistema de legado digital (Posterit-E) utilizando una arquitectura serverless en AWS.
- **Pilar Arquitectónico:** El sistema es Zero-Knowledge. El código del servidor NUNCA debe tener acceso a contraseñas en texto plano o a los secretos del usuario. La criptografía se maneja 100% en el cliente.
- **Regla de Seguridad No Negociable:** Las funciones Lambda solo deben recibir y almacenar datos ya cifrados desde el cliente. Su responsabilidad es gestionar metadatos, flujos de estado y la orquestación del proceso de liberación, pero nunca descifrar información.
- **Stack Tecnológico:** Python, AWS Lambda, API Gateway, DynamoDB, S3.
- **Framework de IaC:** AWS SAM. El archivo `template.yaml` es la única fuente de verdad para la infraestructura de AWS.
- **Tarea Común:** Una tarea típica sería añadir o modificar la lógica de una de las funciones Lambda en `functions/` y actualizar su definición de recursos y permisos en `template.yaml`.
