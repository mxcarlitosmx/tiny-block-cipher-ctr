# Tiny Block Cipher (TBC) - Modo CTR

Este repositorio contiene la implementación en lenguaje C de un algoritmo criptográfico de cifrado por bloques miniatura (16 bits) operando en **Modo Contador (CTR)**. 

El sistema está dividido en dos motores principales: un encriptador (`proyectEncryption.c`) que convierte texto plano en un archivo cifrado en Base64, y un desencriptador (`proyectDecryption.c`) que recupera la información original utilizando la llave simétrica.

## Arquitectura del Cifrador

El núcleo del cifrador (TBC) aplica técnicas de criptografía simétrica a nivel de bits (Bitwise operations) y consta de las siguientes fases por bloque:

* **Expansión de Llaves (Key Expansion):** A partir de una llave aleatoria semilla de 16 bits, el sistema genera dinámicamente 3 subllaves (subkeys) iterativas para aplicar en cada ronda, utilizando operaciones XOR y una función $r(w)$ de rotación de nibbles.
* **Cajas de Sustitución (S-Boxes):** Lectura dinámica de una tabla de sustitución no lineal desde un archivo externo (`CAR_sbox.txt`) para aportar confusión al algoritmo.
* **Cajas de Permutación (P-Boxes):** Aplicación de una máscara fija `{5, 1, 3, 0, 6, 2, 7, 4}` que reordena los bits para garantizar la difusión a lo largo del bloque de datos.
* **Modo CTR (Counter):** Convierte el cifrador de bloques en un cifrador de flujo (Stream Cipher). Genera un vector de inicialización / contador aleatorio ($C_0, C_1$) que se cifra mediante el TBC. El resultado final se obtiene aplicando una operación XOR directa contra el texto plano, lo que permite que la función de descifrado sea estructuralmente idéntica a la de cifrado.

## Stack y Manejo de Datos

* **Lenguaje:** C.
* **Codificación:** Implementación de codificadores y decodificadores **Base64 nativos** (sin librerías externas) para el manejo seguro de las llaves generadas y los archivos binarios resultantes del cifrado.
