# Workshop JWT
Workshop dado el 22/10/2015 sobre Json Web Tokens

***

### Encoder-Decoder
###### Desarrollado en Python 2.7

##### *encode.py*
Ejecutar: `python encode.py`

Devuelve: un JWT token cifrado con el secret `p1t0n-c4p0`

##### *decode.py*
Ejecutar: `python decode.py <token>`

Devuelve: el header y el payload.

##### *verify.py*
Ejecutar: `python verify.py <token> <secret>`

Devuelve: el resultado de la verificacion de la firma del token con el secret ingresado.

***Cada script se puede correr con Docker, cambiando el comando por:
`docker run -it --rm --name encode.py -v "$PWD":/usr/src/myapp -w /usr/src/myapp python:2 python`***

***

### Server JWT
###### Desarrollado en Python 3.4

Se debe correr con el interprete para la version 3.4

Tambien se puede crear un virtual enviroment de python 3.4:

1. `virtualenv -p /usr/bin/python3 venv3.4`
2. `source venv3.4/bin/activate`

Para iniciar el server:

1. Instalar los requerimientos ejecutando `pip install -r requeriments.txt`
2. Iniciar el server ejecutar: `python server.py`
3. Acceder a: [http://0.0.0.0:5000/](http://0.0.0.0:5000/)

Se incluye un Dockerfile para armar un container para correr el server:

* Crearlo con: `docker build -t <nombre_imagen> .`
* Correrlo con: `docker run --name <nombre_container> -p 5000:5000 -i -t <nombre_imagen>`
