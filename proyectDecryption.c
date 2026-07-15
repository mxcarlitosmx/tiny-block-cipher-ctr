#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// PROTOTIPOS DE FUNCIONES
void ctr_decrypt(const char* archivo_cifrado, const char* archivo_llave, const char* archivo_salida);
uint16_t tiny_encrypt(uint16_t M, uint16_t K);
uint32_t* cargarSbox(const char* nombre);
uint8_t r_function(uint8_t w);
void key_expansion(uint16_t K, uint32_t *s_box, uint16_t subkeys[3]);
uint8_t aplicarP(uint8_t s, uint8_t P[8]);

// Funciones utilitarias para Base64 (Solo decodificador)
unsigned char* base64_decode(const char* data, size_t input_length, size_t* output_length);
int b64_index(char c);

// FUNCION PRINCIPAL
int main() {
    char nLlave[100], nCifrado[100], nSalida[100];

    printf(" TINY BLOCK CIPHER: CTR MODE DECRYPTOR\n");

    //Solicitar nombres de archivos al usuario
    printf("Ingrese el nombre del archivo de la CLAVE (Base64): ");
    scanf("%s", nLlave);

    printf("Ingrese el nombre del archivo CIFRADO (Base64): ");
    scanf("%s", nCifrado);

    printf("Ingrese el nombre para el archivo de TEXTO PLANO recuperado: ");
    scanf("%s", nSalida);

    //Llamamos a la funcion que encapsula todo el descifrado CTR
    ctr_decrypt(nCifrado, nLlave, nSalida);

    return 0;
}

//MODO CTR (DESCIFRADO)
void ctr_decrypt(const char* archivo_cifrado, const char* archivo_llave, const char* archivo_salida) {
    FILE *f_key = fopen(archivo_llave, "r");
    FILE *f_cip = fopen(archivo_cifrado, "r");

    if (!f_key || !f_cip) {
        printf("Error: No se pudieron abrir los archivos de entrada.\n");
        return;
    }

    // 1. Leer y decodificar la Llave K desde Base64
    char buffer_key[256] = {0};
    fread(buffer_key, 1, 255, f_key);
    fclose(f_key);

    size_t key_len = 0;
    unsigned char* decoded_key = base64_decode(buffer_key, strlen(buffer_key), &key_len);
    
    // Convertir los bytes decodificados a un uint16_t
    uint16_t K = (uint16_t)((decoded_key[0] << 8) | decoded_key[1]);
    free(decoded_key);

    // 2. Leer y decodificar el Texto Cifrado desde Base64
    fseek(f_cip, 0, SEEK_END);
    long file_size = ftell(f_cip);
    fseek(f_cip, 0, SEEK_SET);

    char* buffer_cifrado = malloc(file_size + 1);
    fread(buffer_cifrado, 1, file_size, f_cip);
    buffer_cifrado[file_size] = '\0';
    fclose(f_cip);

    size_t data_len = 0;
    unsigned char* decoded_data = base64_decode(buffer_cifrado, file_size, &data_len);
    free(buffer_cifrado);

    // 3. Extraer el Contador (Los primeros 2 bytes del archivo decodificado)
    if (data_len < 2) {
        printf("Error: El archivo cifrado esta corrupto o vacio.\n");
        return;
    }
    unsigned char C0 = decoded_data[0];
    unsigned char C1 = decoded_data[1];

    printf("\n--- INICIANDO DESCIFRADO ---\n");
    printf("Llave (K) recuperada: 0x%04X\n", K);
    printf("Contador Inicial Recuperado (C0, C1): 0x%02X 0x%02X\n", C0, C1);
    printf("Descifrando %zu bytes...\n", data_len - 2);

    // 4. Abrir archivo de salida para guardar el texto plano
    FILE *f_out = fopen(archivo_salida, "wb");
    if (!f_out) {
        printf("Error: No se pudo crear el archivo de salida.\n");
        free(decoded_data);
        return;
    }

    //Bucle principal de descifrado CTR
    // Empezamos desde el indice 2 porque los indices 0 y 1 son el contador
    size_t i;
    for (i = 2; i < data_len; i += 2) {
        // Formar el bloque contador de 16 bits
        uint16_t bloque_contador = (uint16_t)((C0 << 8) | (C1 & 0xFF));

        // En modo CTR, el descifrado usa la misma funcion de cifrado sobre el contador
        uint16_t Oi = tiny_encrypt(bloque_contador, K);

        // XOR para recuperar el primer caracter
        unsigned char m0 = decoded_data[i] ^ (unsigned char)(Oi >> 8);
        fputc(m0, f_out);

        // XOR para recuperar el segundo caracter (si existe)
        if (i + 1 < data_len) {
            unsigned char m1 = decoded_data[i + 1] ^ (unsigned char)(Oi & 0xFF);
            fputc(m1, f_out);
        }

        // Incrementar el contador 
        C1++;
    }

    fclose(f_out);
    free(decoded_data);

    printf("[EXITO] Texto recuperado y guardado en %s\n", archivo_salida);
    printf("--- FIN DEL DESCIFRADO ---\n\n");
}

// MOTOR TBC 
uint16_t tiny_encrypt(uint16_t M, uint16_t K) {
    // Leer el Sbox desde archivo sin intervencion del usuario.
    static uint32_t *s_box = NULL;
    if (s_box == NULL) {
        s_box = cargarSbox("CAR_sbox.txt"); 
        if (!s_box) {
            printf("Error critico: No se encontro CAR_sbox.txt\n");
            exit(1);
        }
    }

    // Permutacion fija 
    uint8_t P[8] = {5, 1, 3, 0, 6, 2, 7, 4}; 

    uint16_t subkeys[3];
    key_expansion(K, s_box, subkeys);

    uint16_t estado = M;
    int i;
    for (i = 0; i < 3; i++) {
        estado ^= subkeys[i];
        uint8_t alto = (uint8_t)s_box[(estado >> 8) & 0xFF];
        uint8_t bajo = (uint8_t)s_box[estado & 0xFF];
        
        alto = aplicarP(alto, P);
        bajo = aplicarP(bajo, P);
        
        estado = (uint16_t)((alto << 8) | bajo);
    }
    return estado;
}

uint8_t aplicarP(uint8_t s, uint8_t P[8]) {
    uint8_t resultado = 0;
    int i;
    for (i = 0; i < 8; i++) {
        uint8_t bit = (s >> P[i]) & 1;
        resultado |= (bit << i);
    }
    return resultado;
}

void key_expansion(uint16_t K, uint32_t *s_box, uint16_t subkeys[3]) {
    uint8_t w0 = (uint8_t)(K >> 8);
    uint8_t w1 = (uint8_t)(K & 0xFF);
    subkeys[0] = K; 
    uint8_t w2 = (uint8_t)(w0 ^ 0x80 ^ (uint8_t)s_box[r_function(w1)]);
    uint8_t w3 = (uint8_t)(w2 ^ w1);
    subkeys[1] = (uint16_t)((w2 << 8) | w3); 
    uint8_t w4 = (uint8_t)(w2 ^ 0x30 ^ (uint8_t)s_box[r_function(w3)]);
    uint8_t w5 = (uint8_t)(w4 ^ w3);
    subkeys[2] = (uint16_t)((w4 << 8) | w5); 
}

uint8_t r_function(uint8_t w) {
    return (uint8_t)((w << 4) | (w >> 4));
}

uint32_t* cargarSbox(const char* nombre) {
    FILE *file = fopen(nombre, "r");
    if (!file) return NULL;
    uint32_t *sbox = malloc(256 * sizeof(uint32_t));
    char linea[100]; unsigned int i, v;
    fgets(linea, sizeof(linea), file); 
    while (fscanf(file, " S(%X) = %X", &i, &v) == 2) sbox[i] = v;
    fclose(file);
    return sbox;
}

// UTILIDADES BASE 64
int b64_index(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

unsigned char* base64_decode(const char* data, size_t input_length, size_t* output_length) {
    if (input_length % 4 != 0) return NULL;
    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;
    
    unsigned char* decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;
    
    size_t i, j = 0;
    for (i = 0, j = 0; i < input_length;) {
        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : b64_index(data[i++]);
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : b64_index(data[i++]);
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : b64_index(data[i++]);
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : b64_index(data[i++]);
        uint32_t triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;
        
        if (j < *output_length) decoded_data[j++] = (triple >> 16) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = triple & 0xFF;
    }
    return decoded_data;
}
