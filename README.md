# shellcodekitchen
==================

Este proyecto nacio como consecuencia de una rapida pasada por [shell-storm](shell-storm.org) en busca de una tipica shellcode exec calc para probar un exploit.

A altas horas de la noche, vi que habia versiones para XP SP2, SP3, una multiwindow... pero al momento de verificar el link, todas estaban o en codigo asm lista para compilarlas, o el choclo en hexa.

Cada vez que copy/pasteo una shellcode en hexa, tengo esa incertidumbre de no saber si "me estoy owneando solo"

Por eso arranque con shellcodekitchen.

shellcodekitchen es una libreria en python que encapsula todo el choclo hexa dentro del objeto, y nos provee metodos como:

* getlibrary: camina por las estructuras LDR en busca de la direccion base de la libreria que se le pasa como argumento.
* syscall: ejecuta la funcion con los argumentos que le pasemos.

Luego de ejecutar las acciones que nos interesan, podemos descargar el raw del shellcode haciendo getfruit y pasandolo al exploit.

Hay que hacer enfasis en que esta libreria usa metaprogramacion, por ahora la sehellcode solo provee el hexa para realizar la operacion, pero no retorna ningun feedback o SUCCESS.

Tambien subi un exploitme que resolvi para que sirva como ejemplo del funcionamiento de shellcodekitchen.

El exploitme nos presenta un socket en el puerto 65535, en el cual entrega un servicio mediante un protocolo custom, si se toquetean un poco los datos del protocolo se provoca un integer overflow que desencadena un stack overflow y permite ejecucion remota.

![alt tag](https://raw.githubusercontent.com/pastaCLS/shellcodekitchen/master/img/exploitme.png)

El exploit-egg.py se le tiene que pasar la ip de la maquina y el comando a ejecutar. El comando sera el argumento que le enviaremos a shellcodekitchen para que nos arme la shellcode exec.


![alt tag](https://raw.githubusercontent.com/pastaCLS/shellcodekitchen/master/img/trigger1.png)

Ejecuta la calc y sale del exploitme:

![alt tag](https://raw.githubusercontent.com/pastaCLS/shellcodekitchen/master/img/calc.png)

Se le puede pasar otro CMD, como por ejemplo cmd.exe:

![alt tag](https://raw.githubusercontent.com/pastaCLS/shellcodekitchen/master/img/trigger2.png)

Y transformamos nuestro exploitme en la linea de comandos:

![alt tag](https://raw.githubusercontent.com/pastaCLS/shellcodekitchen/master/img/cmd.png)

Por el momento shellcodekitchen, no da ninguna feature que no se podria conseguir con cualquier shell construida con msfvenom, pero a la hora de codearla es mucho mas intuitiva:

```python
from shellcodekitchen.core import *

shellcode = BaseWin32Shellcode()
shellcode.syscall("WinExec", sys.argv[2])
shellcode.quit()

send(shellcode.getfruit())
```

El modulo ya provee un objeto hijo de BaseWin32Shellcode que encapsula ese codigo, llamado muy originalmente ExecShellcode.
