#include <stdio.h>
#include <stdint.h>
#include <string.h>

//#define DEBUG_COMPILATION_FLAG

#ifdef DEBUG_COMPILATION_FLAG

    #define DEBUG_KEY_EXPANSION

    #define DEBUG_MIX_COLUMNS_TRANSFORMATION

    #define DEBUG_SUBSTITUTE_BYTES_TRANSFORMATION

#endif

const uint8_t S_BOX[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// Constantes de ronda
const uint32_t ROUND_CONSTANT[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

const uint8_t MIX_COLUMNS[16] = {
    0x02, 0x03, 0x01, 0x01,
    0x01, 0x02, 0x03, 0x01,
    0x01, 0x01, 0x02, 0x03,
    0x03, 0x01, 0x01, 0x02
};

void printMatrix (uint8_t (*inputMatrix)[4])
{
    for (uint8_t j = 0; j < 4; j++){
        printf("%02X %02X %02X %02X\r\n", inputMatrix[0][j], inputMatrix[1][j], inputMatrix[2][j], inputMatrix[3][j]);
    }

    printf("\r\n");
}

// Expansión de clave AES
void KeyExpansion(uint8_t *key, uint32_t *w) {
    
    uint32_t g_funcion_output = 0;

    uint8_t b0 = 0, b1 = 0, b2 = 0, b3 = 0;

    for (uint8_t i = 0; i < 4; i++)
    {   
        #ifdef DEBUG_KEY_EXPANSION
            printf("\r\nKey Expansion Round %02d\r\n", i);
        #endif

        w[i] = (key[4*i] << 24) | (key[4*i + 1] << 16) | (key[4*i + 2] <<  8) | (key[4*i + 3]);

        #ifdef DEBUG_KEY_EXPANSION
            printf("w%02d: %02X %02X %02X %02X\r\n", i, key[4*i], key[4*i + 1], key[4*i + 2], key[4*i + 3]);
        #endif
    }

    for (uint8_t i = 4; i < 44; ++i)
    {   
        #ifdef DEBUG_KEY_EXPANSION
            printf("\r\nKey Expansion Round %02d\r\n", i);
        #endif

        // Calculate output of g function
        if (i % 4 == 0) {

            #ifdef DEBUG_KEY_EXPANSION
                printf("\r\nCalculating g function:\r\n\r\n");
            #endif

            // Get W[i-1] bytes
            b0 = (w[i - 1] >> 24) & 0xFF;
            b1 = (w[i - 1] >> 16) & 0xFF;
            b2 = (w[i - 1] >>  8) & 0xFF;
            b3 =  w[i - 1]        & 0xFF;

            // Rotate Word Transformation
            #ifdef DEBUG_KEY_EXPANSION
                printf("Mix Columns Transformation: %02X %02X %02X %02X\r\n", b1, b2, b3, b0);
            #endif

            // Substitute Bytes Transformation
            g_funcion_output = (S_BOX[b1] << 24) | (S_BOX[b2] << 16) | (S_BOX[b3] << 8) | (S_BOX[b0]);

            #ifdef DEBUG_KEY_EXPANSION
                printf("Substitute Bytes Transformation: %02X %02X %02X %02X\r\n",(g_funcion_output >> 24) & 0xFF, (g_funcion_output >> 16) & 0xFF, (g_funcion_output >> 8) & 0xFF, (g_funcion_output) & 0xFF);
            #endif

            // XOR with Round Constant
            g_funcion_output ^= ROUND_CONSTANT[i / 4 - 1] << 24;

            #ifdef DEBUG_KEY_EXPANSION
                printf("Round %02d Constant: %02X 00 00 00\r\n", i, ROUND_CONSTANT[i / 4 - 1]);

                printf("XOR with Round Constant: %02X %02X %02X %02X\r\n", ((g_funcion_output >> 24) & 0xFF), ((g_funcion_output >> 16) & 0xFF), ((g_funcion_output >> 8) & 0xFF), (g_funcion_output & 0xFF));

                printf("\r\n");

                printf("w%02d: %02X %02X %02X %02X\r\n", (i - 4), ((w[i - 4] >> 24) & 0xFF), ((w[i - 4] >> 16) & 0xFF), ((w[i - 4] >> 8) & 0xFF), ((w[i - 4]) & 0xFF));

                printf("g%02d: %02X %02X %02X %02X\r\n", i, ((g_funcion_output >> 24) & 0xFF), ((g_funcion_output >> 16) & 0xFF), ((g_funcion_output >> 8) & 0xFF), (g_funcion_output & 0xFF));
            #endif
            
            w[i] = w[i - 4] ^ g_funcion_output;

            #ifdef DEBUG_KEY_EXPANSION
                printf("\r\nRound %02d Key\r\n", i);

                printf("w%02d: %02X %02X %02X %02X\r\n", i, ((w[i] >> 24) & 0xFF), ((w[i] >> 16) & 0xFF), ((w[i] >> 8) & 0xFF), (w[i] & 0xFF));
            #endif
        }

        else
        {   
            #ifdef DEBUG_KEY_EXPANSION
                printf("w%02d: %02X %02X %02X %02X\r\n", (i - 4), ((w[i - 4] >> 24) & 0xFF), ((w[i - 4] >> 16) & 0xFF), ((w[i - 4] >> 8) & 0xFF), ((w[i - 4]) & 0xFF));
                
                printf("w%02d: %02X %02X %02X %02X\r\n", (i - 1), ((w[i - 1] >> 24) & 0xFF), ((w[i - 1] >> 16) & 0xFF), ((w[i - 1] >> 8) & 0xFF), ((w[i - 1]) & 0xFF));
            #endif

            w[i] = w[i - 4] ^ w[i - 1];

            #ifdef DEBUG_KEY_EXPANSION
                printf("\r\nRound %02d Key\r\n", i);

                printf("w%02d: %02X %02X %02X %02X\r\n", i, ((w[i] >> 24) & 0xFF), ((w[i] >> 16) & 0xFF), ((w[i] >> 8) & 0xFF), (w[i] & 0xFF));
            #endif
        }

        #ifdef DEBUG_KEY_EXPANSION
            printf("\r\n");
        #endif
    }
}

void printExpandedKey(uint32_t *w)
{
    uint8_t BytesWord[4];
    
    printf("Expanded Key:\r\n");

    for (uint8_t roundNumber = 0; roundNumber < 11; roundNumber++)
    {
        for (uint8_t i = 0; i < 4; i++)
        {
            BytesWord[0] = (w[4*roundNumber+ i] >> 24) & 0xFF;
            BytesWord[1] = (w[4*roundNumber+ i] >> 16) & 0xFF;
            BytesWord[2] = (w[4*roundNumber+ i] >>  8) & 0xFF;
            BytesWord[3] = (w[4*roundNumber+ i]      ) & 0xFF;

            for (uint8_t j = 0; j < 4; j++) printf("0x%02X ", BytesWord[j]);

            printf("\r\n");

        }

        printf("\r\n");
    }
}

void allocateRoundKey(uint8_t (*roundKey)[4], uint32_t *w, uint8_t roundNumber)
{
    for (uint8_t i = 0; i < 4; i++)
    {
        roundKey[i][0] = ((w[4*roundNumber + i] >> 24) & 0xFF);
        roundKey[i][1] = ((w[4*roundNumber + i] >> 16) & 0xFF);
        roundKey[i][2] = ((w[4*roundNumber + i] >>  8) & 0xFF);
        roundKey[i][3] = ((w[4*roundNumber + i]      ) & 0xFF);
    }
}

void AddRoundKeyTransformation(uint8_t (*roundState)[4], uint8_t (*roundKey)[4])
{
    for (uint8_t i = 0; i < 4; i++)
    { 
        for (uint8_t j = 0; j < 4; j++)
        {
            roundState[i][j] ^= roundKey[i][j];
        }
    }
}

void SubstituteBytesTransformation (uint8_t (*sIn)[4])
{
    uint8_t sBoxIndex;

    for (uint8_t i = 0; i < 4; i++)
    {
        for (uint8_t j = 0; j < 4; j++)
        {
            #ifdef DEBUG_SUBSTITUTE_BYTES_TRANSFORMATION
                printf("\r\nInput Byte: 0x%02X\r\n", sIn[i][j]);

                printf("sBoxIndex: x=%02d y=%02d\r\n", (sIn[i][j] & 0x0F), ((sIn[i][j] & 0xF0) >> 4));
            #endif

            sBoxIndex = 16*((sIn[i][j] & 0xF0) >> 4) + (sIn[i][j] & 0x0F);
            
            sIn[i][j] = S_BOX[sBoxIndex];

            #ifdef DEBUG_SUBSTITUTE_BYTES_TRANSFORMATION
                printf("Output Byte: 0x%02X\r\n", sIn[i][j]);
            #endif
        }
    }
}

void SwiftRowsTransformation (uint8_t (*sIn)[4])
{   
    uint8_t sOut[4][4];

    // Row 0
    sOut[0][0] = sIn[0][0];
    sOut[1][0] = sIn[1][0];
    sOut[2][0] = sIn[2][0];
    sOut[3][0] = sIn[3][0];

    // Row 1
    sOut[0][1] = sIn[1][1];
    sOut[1][1] = sIn[2][1];
    sOut[2][1] = sIn[3][1];
    sOut[3][1] = sIn[0][1];

    // Row 2
    sOut[0][2] = sIn[2][2];
    sOut[1][2] = sIn[3][2];
    sOut[2][2] = sIn[0][2];
    sOut[3][2] = sIn[1][2];

    // Row 3
    sOut[0][3] = sIn[3][3];
    sOut[1][3] = sIn[0][3];
    sOut[2][3] = sIn[1][3];
    sOut[3][3] = sIn[2][3];
    
    for (uint8_t i = 0; i < 4; i++)
    {
        for (uint8_t j = 0; j < 4; j++)
        {
            sIn[i][j] = sOut[i][j];
        }
    }
}


uint8_t galoisMultiplication(uint8_t a, uint8_t b)
{
    uint8_t result = 0x00; uint8_t overflow = 0x00;

    // Realizar las siguientes operaciones para los 8 bits de byte B.
    for (uint8_t i = 0; i < 8; i++)
    {
        // Si el LSB del byte B está activo (B AND 0x01) entonces:
        // · Se añade el valor del byte A al valor acumulado en el byte resultado (XOR).
        if (b & 0x01) result = result ^ a;
        
        // Si el MSB del byte A está activo (A AND 0x80) entonces:
        // · Se ha producido un overflow
        // · Se deberá realizar una reducción del byte A con el polinomio irreducible 0x1B (x^8 + x^4 + x^3 + x + 1).
        overflow = a & 0x80;

        // Deplazar hacia la derecha los bits del byte A (introducir ceros en el LSB)
        a = a << 1;

        // Si se ha detectado un overflow en el byte A entonces:
        // · Se realiza la operacion XOR entre el byte A y el polinomio irreducible 0x1B.
        if (overflow) a = a ^0x1B;

        // Deplazar hacia la izquierda los bits del byte B (introducir ceros en el MSB)
        b = b >> 1;
    }

    return result;
}

void MixColumnsTransformation (uint8_t (*sIn)[4])
{
    uint8_t sOut[4][4];

    for (uint8_t i = 0; i < 4; i++)
    {   
        #ifdef DEBUG_MIX_COLUMNS_TRANSFORMATION
            printf("\r\n%02X\r\n%02X\r\n%02X\r\n%02X\r\n", sIn[i][0], sIn[i][1], sIn[i][2], sIn[i][3]);
        #endif

        sOut[i][0] = galoisMultiplication(sIn[i][0], 0x02) ^ galoisMultiplication(sIn[i][1], 0x03) ^ sIn[i][2] ^ sIn[i][3];
        sOut[i][1] = sIn[i][0] ^ galoisMultiplication(sIn[i][1], 0x02) ^ galoisMultiplication(sIn[i][2], 0x03) ^ sIn[i][3];
        sOut[i][2] = sIn[i][0] ^ sIn[i][1] ^ galoisMultiplication(sIn[i][2], 0x02) ^ galoisMultiplication(sIn[i][3], 0x03);
        sOut[i][3] = galoisMultiplication(sIn[i][0], 0x03) ^ sIn[i][1] ^ sIn[i][2] ^ galoisMultiplication(sIn[i][3], 0x02);

        #ifdef DEBUG_MIX_COLUMNS_TRANSFORMATION
            printf("\r\nsOut[%d][0] = (02 · %02X) XOR (03 · %02X) XOR %02X XOR %02X = %02X\r\n", i, sIn[i][0], sIn[i][1], sIn[i][2], sIn[i][3], sOut[i][0]);
            printf("\r\nsOut[%d][1] = %02X XOR (02 · %02X) XOR (03 · %02X) XOR %02X = %02X\r\n", i, sIn[i][0], sIn[i][1], sIn[i][2], sIn[i][3], sOut[i][1]);
            printf("\r\nsOut[%d][2] = %02X XOR %02X XOR (02 · %02X) XOR (03 · %02X) = %02X\r\n", i, sIn[i][0], sIn[i][1], sIn[i][2], sIn[i][3], sOut[i][2]);
            printf("\r\nsOut[%d][3] = (03 · %02X) XOR %02X XOR %02X XOR (02 · %02X) = %02X\r\n", i, sIn[i][0], sIn[i][1], sIn[i][2], sIn[i][3], sOut[i][3]);
        #endif
    }

    for (uint8_t i = 0; i < 4; i++)
    {
        for (uint8_t j = 0; j < 4; j++)
        {
            sIn[i][j] = sOut[i][j];
        }
    }
}

void aes_encryption (uint8_t *plainText, uint8_t *key, uint8_t *cipherText)
{
    uint32_t expandedKey[44];

    uint8_t roundKey[4][4], roundState[4][4];

    KeyExpansion(key, expandedKey);

    // Allocate the plain text in the input state
    for (uint8_t i = 0; i < 4; i++) for (uint8_t j = 0; j < 4; j++) roundState[i][j] = plainText[4*i + j];
    
    printf("Plain Text:\r\n");
    printMatrix(roundState);

    // Allocate the round key
    allocateRoundKey(roundKey, expandedKey, 0);
    
    printf("Round Key:\r\n");
    printMatrix(roundKey);

    AddRoundKeyTransformation(roundState, roundKey);

    printf("Round State:\r\n");
    printMatrix(roundState);

    for (uint8_t round = 1; round < 11; round++)
    {
        printf("Round %02d:\r\n", round);
        printf("\r\n");

        SubstituteBytesTransformation(roundState);

        printf("Substitute Bytes:\r\n");
        printMatrix(roundState);

        SwiftRowsTransformation(roundState);

        printf("Swift Rows:\r\n");
        printMatrix(roundState);

        if (round != 10)
        {
            MixColumnsTransformation(roundState);

            printf("Mix Columns:\r\n");
            printMatrix(roundState);
        }
               
        allocateRoundKey(roundKey, expandedKey, round);

        printf("Round Key:\r\n");
        printMatrix(roundKey);

        AddRoundKeyTransformation(roundState, roundKey);

        printf("Add Round Key:\r\n");
        printMatrix(roundState);
    }
    
    memcpy(cipherText, roundState, sizeof(roundState));

}

int main(int argc, char *argv[])
{
    uint8_t key[16] = {0x0F, 0x15, 0x71, 0xC9, 0x47, 0xD9, 0xE8, 0x59, 0x0C, 0xB7, 0xAD, 0xD6, 0xAF, 0x7F, 0x67, 0x98};
    
    uint8_t plainText[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    
    uint8_t cipherText[16];
    
    aes_encryption(plainText, key, cipherText);

    printf("Cipher Text: ");

    for (int i = 0; i < 16; ++i) {
        printf("0x%02X ", cipherText[i]);
    }

    printf("\r\n");

    return 0;
}

