#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

// PROTOTIPOS DE FUNCIONES
void generateKey64(const char* archivo_llave);
void ctr_encrypt(const char* archivo_plano, const char* archivo_llave, const char* archivo_salida);
uint16_t tiny_encrypt(uint16_t M, uint16_t K);
uint32_t* cargarSbox(const char* nombre);
uint8_t r_function(uint8_t w);
void key_expansion(uint16_t K, uint32_t *s_box, uint16_t subkeys[3]);
uint8_t aplicarP(uint8_t s, uint8_t P[8]);

// Funciones utilitarias para Base64
char* base64_encode(const unsigned char* data, size_t input_length, size_t* output_length);
unsigned char* base64_decode(const char* data, size_t input_length, size_t* output_length);
int b64_index(char c);


//Main
int main() {
    char nPlano[100], nLlave[100], nSalida[100];
    int opcion;

    // Inicializar semilla para la aleatoriedad (Llave y C0)
    srand((unsigned int)time(NULL));

    printf(" TINY BLOCK CIPHER: CTR MODE ENCRYPTOR\n");

    //Funcion para generar una llave aleatoria y guardarla en base64
    printf("Desea generar una nueva llave aleatoria? (1=Si, 0=No): ");
    scanf("%d", &opcion);
    if (opcion == 1) {
        printf("Ingrese el nombre para el nuevo archivo de LLAVE: ");
        scanf("%s", nLlave);
        generateKey64(nLlave);
        printf("[EXITO] Llave generada y guardada en %s\n\n", nLlave);
    }

    //Solicitar nombres de archivos al usuario
    printf("Ingrese el nombre del archivo de TEXTO PLANO a cifrar: ");
    scanf("%s", nPlano);

    printf("Ingrese el nombre del archivo de la CLAVE a utilizar: ");
    scanf("%s", nLlave);

    //El nombre del archivo de salida debe ser elegido por el usuario
    printf("Ingrese el nombre del archivo CIFRADO de SALIDA: ");
    scanf("%s", nSalida);

    //Llamamos a la funcion que encapsula todo el cifrado CTR
    ctr_encrypt(nPlano, nLlave, nSalida);

    return 0;
}

//Funcion para generar llaves aleatorias
void generateKey64(const char* archivo_llave) {
    uint16_t llave_aleatoria = (uint16_t)(rand() % 65536); // Genera 16 bits al azar
    unsigned char llave_bytes[2];
    llave_bytes[0] = (llave_aleatoria >> 8) & 0xFF;
    llave_bytes[1] = llave_aleatoria & 0xFF;

    size_t out_len;
    char* base64_llave = base64_encode(llave_bytes, 2, &out_len);

    FILE *f_key = fopen(archivo_llave, "w");
    if (f_key) {
        fprintf(f_key, "%s", base64_llave);
        fclose(f_key);
    }
    free(base64_llave);
}

//Funcion modo CTR
void ctr_encrypt(const char* archivo_plano, const char* archivo_llave, const char* archivo_salida) {
    FILE *f_key = fopen(archivo_llave, "r");
    FILE *f_plain = fopen(archivo_plano, "rb");

    if (!f_key || !f_plain) {
        printf("Error: No se pudieron abrir los archivos de entrada.\n");
        return;
    }

    // 1. Leer y decodificar la Llave K desde Base64
    char buffer_key[256] = {0};
    fread(buffer_key, 1, 255, f_key);
    fclose(f_key);

    size_t key_len = 0;
    unsigned char* decoded_key = base64_decode(buffer_key, strlen(buffer_key), &key_len);
    uint16_t K = (uint16_t)((decoded_key[0] << 8) | decoded_key[1]);
    free(decoded_key);

    // 2. Leer el Texto Plano completo
    fseek(f_plain, 0, SEEK_END);
    long plain_size = ftell(f_plain);
    fseek(f_plain, 0, SEEK_SET);

    unsigned char* plaintext = malloc(plain_size);
    fread(plaintext, 1, plain_size, f_plain);
    fclose(f_plain);

    //Preparar el buffer de salida (Tamaño: Contador(2 bytes) + Texto Cifrado)
    size_t cipher_size = plain_size + 2;
    unsigned char* ciphertext = malloc(cipher_size);

    //Generar el contador de forma aleatoria (C0 = random, C1 = 0)
    unsigned char C0 = (unsigned char)(rand() % 256);
    unsigned char C1 = 0;
    
    // Guardar el contador en los primeros 2 bytes de la salida
    ciphertext[0] = C0;
    ciphertext[1] = C1;

    printf("\n--- INICIANDO CIFRADO ---\n");
    printf("Llave (K) utilizada: 0x%04X\n", K);
    printf("Contador Inicial Generado (C0, C1): 0x%02X 0x%02X\n", C0, C1);
    printf("Cifrando %ld bytes...\n", plain_size);

    //Bucle principal de cifrado CTR
    size_t i = 0;
    for (i = 0; i < plain_size; i += 2) {
        uint16_t bloque_contador = (uint16_t)((C0 << 8) | (C1 & 0xFF));

        //Llamar a TBC pasandole solo (M, K)
        uint16_t Oi = tiny_encrypt(bloque_contador, K);

        // XOR para cifrar el primer caracter
        ciphertext[i + 2] = plaintext[i] ^ (unsigned char)(Oi >> 8);

        // XOR para cifrar el segundo caracter (si el archivo tiene longitud impar)
        if (i + 1 < plain_size) {
            ciphertext[i + 3] = plaintext[i + 1] ^ (unsigned char)(Oi & 0xFF);
        }

        C1++; // Incrementar contador
    }

    //Codificar TODO el resultado (Contador + Cifrado) en Base64
    size_t b64_len;
    char* final_base64 = base64_encode(ciphertext, cipher_size, &b64_len);

    // Guardar en el archivo de salida
    FILE* f_out = fopen(archivo_salida, "w");
    if (f_out) {
        fprintf(f_out, "%s", final_base64);
        fclose(f_out);
        printf("[EXITO] Archivo cifrado y guardado en %s\n", archivo_salida);
    }

    printf("--- FIN DEL CIFRADO ---\n\n");

    free(plaintext);
    free(ciphertext);
    free(final_base64);
}


//Tiny Block Cipher
uint16_t tiny_encrypt(uint16_t M, uint16_t K) {
    //Leer el Sbox desde archivo sin intervencion del usuario.
    static uint32_t *s_box = NULL;
    if (s_box == NULL) {
        //Nombre SBOX
        s_box = cargarSbox("CAR_sbox.txt"); 
        if (!s_box) {
            printf("Error critico: No se encontro XYZ_sbox.txt\n");
            exit(1);
        }
    }

    //Permutacion fija 
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
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* base64_encode(const unsigned char* data, size_t input_length, size_t* output_length) {
    *output_length = 4 * ((input_length + 2) / 3);
    char* encoded_data = malloc(*output_length + 1);
    if (encoded_data == NULL) return NULL;
    size_t i, j = 0;
   // int i = 0;
    for (i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
        encoded_data[j++] = b64_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = b64_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = b64_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = b64_table[(triple >> 0 * 6) & 0x3F];
    }
    for (i = 0; i < (3 - input_length % 3) % 3; i++)
        encoded_data[*output_length - 1 - i] = '=';
    encoded_data[*output_length] = '\0';
    return encoded_data;
}

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
    size_t i, j= 0;
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
