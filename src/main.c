#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
/*******************************宏*****************************/
#define Nb 4  /* 分组长度　Block size in words, 4/4/4 for AES-128/192/256 */
#define Nk 8  /* 密钥长度　column number, as of 4xNk, 4/6/8 for AES-128/192/256 */
#define Nr 14 /* 加密轮数　Number of rounds, 10/12/14 for AES-128/192/256 */
#define BLOCK_SIZE 16
#define Rb 0x87
// #define test_Encrypt//用于加密过程测试
// #define test_Decrypt//用于解密过程测试
// #define test_CMAC//用CMAC过程测试
/*************************************************************/

/***************************固定常量**************************/
/* S_BOX Ｓ盒 */
static const uint8_t sbox[16][16] = {
    /* 0     1    2      3     4    5     6     7      8     9     A     B     C     D     E     F  */
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
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};
/* Reverse S_BOX 反向Ｓ盒　*/
static const uint8_t rsbox[16][16] = {
    /* 0     1    2      3     4    5     6     7      8     9     A     B     C     D     E     F  */
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D};
/* 轮常数 */
static const uint8_t rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
/* 列混合左乘固定矩阵,取其转置右乘 */
static const uint8_t MixArr[16] = {
    0x02, 0x01, 0x01, 0x03,
    0x03, 0x02, 0x01, 0x01,
    0x01, 0x03, 0x02, 0x01,
    0x01, 0x01, 0x03, 0x02};
/* 逆列混合左乘固定矩阵,取其转置右乘 */
static const uint8_t rMixArr[16] = {
    0x0e, 0x09, 0x0d, 0x0b,
    0x0b, 0x0e, 0x09, 0x0d,
    0x0d, 0x0b, 0x0e, 0x09,
    0x09, 0x0d, 0x0b, 0x0e};
/*************************************************************/

/***************************函数声明**************************/
void aes_EncryptState(uint8_t *plaintext, uint8_t *expanded_key, uint8_t *ciphertext);
void aes_DecryptState(uint8_t *ciphertext, uint8_t *expanded_key, uint8_t *plaintext);
void aes_CMAC(uint8_t *message, uint8_t *key, uint8_t *mac);
void test();
/*************************************************************/

int main()
{
    test();
    return 0;
}

/* 打印分组数据 Print state  */
void print_state(const uint8_t *s)
{
    int i, j;
    for (i = 0; i < 16; i++)
    {
        printf("%02x", s[i]);
        printf(" ");
        if ((i + 1) % 4 == 0)
        {
            printf("\n");
        }
    }
    printf("\n");
}

/* 矩阵转置 */
uint8_t *InvMatrix(uint8_t *p)
{
    uint8_t temp[16];
    memcpy(temp, p, 16);
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            p[4 * j + i] = temp[4 * i + j];
        }
    }
    return p;
}

/*GF(2^8)加法*/
uint8_t gf_Add(uint8_t a, uint8_t b)
{
    return a ^ b; // 在 GF(2^8) 中，加法就是异或运算
}

/*GF(2^8)乘法*/
uint8_t gf_Multiply(uint8_t a, uint8_t b)
{
    uint8_t result = 0;
    while (b > 0)
    {
        if (b & 1)               // 如果 b 的最低位为 1
            result ^= a;         // 就将 a 加到结果中
        if (a & 0x80)            // 如果 a 的最高位为 1
            a = (a << 1) ^ 0x1B; // a 乘以 x(左移)，然后模上 x^8 + x^4 + x^3 + x + 1
        else
            a <<= 1; // 否则只是简单地将 a 左移一位
        b >>= 1;     // 将 b 右移一位
    }
    return result;
}

/*GF(2^8)除法*/
uint8_t gf_Divide(uint8_t a, uint8_t b)
{
    if (b == 0)
        return 0; // 除数为零，返回零
    if (a == 0)
        return 0; // 被除数为零，返回零

    uint8_t quotient = 0;
    uint8_t remainder = a;

    while (b >= remainder)
    {
        int shift_amount = 0;
        while ((b << shift_amount) < remainder)
            shift_amount++;
        uint8_t divisor = b << shift_amount;
        quotient ^= (1 << shift_amount);
        remainder ^= divisor;
    }

    return quotient;
}

/* 循环左移一个字节 */
void rot_word(uint8_t *word)
{
    uint8_t temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

/* 循环右移一个字节 */
void rot_word_right(uint8_t *word)
{
    uint8_t temp = word[3];
    word[3] = word[2];
    word[2] = word[1];
    word[1] = word[0];
    word[0] = temp;
}

/* 字节替换 1:正向*/
void aes_SubBytes(uint8_t *state, int st)
{
    if (st)
    {
        for (int i = 0; i < 16; i++)
        {
            state[i] = sbox[(uint8_t)(state[i] >> 4)][(uint8_t)(state[i] & 0x0f)];
        }
    }
    else
    {
        for (int i = 0; i < 16; i++)
        {
            state[i] = rsbox[(uint8_t)(state[i] >> 4)][(uint8_t)(state[i] & 0x0f)];
        }
    }
}

/* 行移位 左移*/
void aes_ShiftRows(uint8_t *state)
{
    uint8_t tmp[4];
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            tmp[j] = state[4 * j + i];
        }
        int round = i;
        while (round)
        {
            rot_word(tmp);
            round--;
        }
        for (int j = 0; j < 4; j++)
        {
            state[4 * j + i] = tmp[j];
        }
    }
}

/* 逆行移位 右移 */
int aes_InvShiftRows(uint8_t *state)
{
    uint8_t tmp[4];
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            tmp[j] = state[4 * j + i];
        }
        int round = i;
        while (round)
        {
            rot_word_right(tmp);
            round--;
        }
        for (int j = 0; j < 4; j++)
        {
            state[4 * j + i] = tmp[j];
        }
    }
}

/* 列混合 */
void aes_MixColums(uint8_t *state)
{
    uint8_t tmp[4];
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            tmp[j] = state[4 * i + j]; // 缓存状态矩阵的行
        }

        for (int m = 0; m < 4; m++)
        {                         // 求新行（4个元素）
            state[4 * i + m] = 0; // 新行先置为0
            for (int n = 0; n < 4; n++)
            { // 求新行元素
                state[4 * i + m] ^= gf_Multiply(tmp[n], MixArr[m + 4 * n]);
            }
        }
    }
}

/* 逆列混合 */
void aes_InvMixColums(uint8_t *state)
{
    uint8_t tmp[4];
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            tmp[j] = state[4 * i + j]; // 缓存状态矩阵的行
        }

        for (int m = 0; m < 4; m++)
        {                         // 求新行（4个元素）
            state[4 * i + m] = 0; // 新行先置为0
            for (int n = 0; n < 4; n++)
            { // 求新行元素
                state[4 * i + m] ^= gf_Multiply(tmp[n], rMixArr[m + 4 * n]);
            }
        }
    }
}

/* 字替换操作 */
void sub_word(uint8_t *word)
{
    for (int i = 0; i < 4; i++)
    {
        word[i] = sbox[(uint8_t)(word[i] >> 4)][(uint8_t)(word[i] & 0x0f)];
    }
}

/* 密钥扩展函数 */
void aes_Keyexpansion(uint8_t *key, uint8_t *expanded_key)
{
    uint8_t temp[4] = {0};
    int i = 0;

    // 首先将初始密钥复制到扩展密钥的前NK字节
    while (i < Nk)
    {
        expanded_key[4 * i] = key[4 * i];
        expanded_key[4 * i + 1] = key[4 * i + 1];
        expanded_key[4 * i + 2] = key[4 * i + 2];
        expanded_key[4 * i + 3] = key[4 * i + 3];
        i++;
    }

    // 逐步生成扩展密钥的剩余部分
    i = Nk;
    while (i < Nb * (Nr + 1))
    {
        // 从前一字的末尾提取4字节，存储到temp中
        temp[0] = expanded_key[4 * (i - 1)];
        temp[1] = expanded_key[4 * (i - 1) + 1];
        temp[2] = expanded_key[4 * (i - 1) + 2];
        temp[3] = expanded_key[4 * (i - 1) + 3];

        if (i % Nk == 0)
        {
            // 若i是NK的倍数，对temp进行字节代换和轮常数异或
            rot_word(temp);              // 字循环左移
            sub_word(temp);              // 字节代换
            temp[0] ^= rcon[i / Nk - 1]; // 轮常数异或
        }
        else if (Nk > 6 && i % Nk == 4)
        {
            // 若NK>6且i是NK的中间值，只进行字节代换
            sub_word(temp);
        }

        // 使用前一字和temp异或来生成扩展密钥的下一字
        expanded_key[4 * i + 0] = expanded_key[4 * (i - Nk) + 0] ^ temp[0];
        expanded_key[4 * i + 1] = expanded_key[4 * (i - Nk) + 1] ^ temp[1];
        expanded_key[4 * i + 2] = expanded_key[4 * (i - Nk) + 2] ^ temp[2];
        expanded_key[4 * i + 3] = expanded_key[4 * (i - Nk) + 3] ^ temp[3];
        i++;
    }
}

/* 加轮密钥 */
void aes_Addroundkey(uint8_t *state, uint8_t *round_key, uint8_t round)
{
    for (int i = 0; i < 16; i++)
    {
        state[i] ^= round_key[i + 16 * round]; // 按位异或操作
    }
}

void aes_EncryptState(uint8_t *plaintext, uint8_t *expanded_key, uint8_t *ciphertext)
{

    uint8_t round = 0;
    memcpy(ciphertext, plaintext, 16);

#ifdef test_Encrypt
    print_state(ciphertext);
    printf("\n");
    /* 1.初始轮密钥加法 */
    aes_Addroundkey(ciphertext, expanded_key, 0);
    print_state(ciphertext);
    printf("\n");
    /* 循环Nr-1轮加密运算 */
    for (round = 1; round < Nr; round++)
    {
        /* 2.字节代换 */
        aes_SubBytes(ciphertext, 1);
        print_state(ciphertext);
        printf("\n");
        /* 3.行移位 */
        aes_ShiftRows(ciphertext);
        print_state(ciphertext);
        printf("\n");
        /* 4.列混合 */
        aes_MixColums(ciphertext);
        print_state(ciphertext);
        printf("\n");
        /* 5.加轮密钥 */
        aes_Addroundkey(ciphertext, expanded_key, round);
        print_state(ciphertext);
        printf("\n");
    }

    /* 6.最后一轮(字节代换，行移位，加轮密钥) */
    aes_SubBytes(ciphertext, 1);
    print_state(ciphertext);
    printf("\n");
    aes_ShiftRows(ciphertext);
    print_state(ciphertext);
    printf("\n");
    aes_Addroundkey(ciphertext, expanded_key, round);
    print_state(ciphertext);
    printf("\n");
#else
    /* 1.初始轮密钥加法 */
    aes_Addroundkey(ciphertext, expanded_key, 0);
    /* 循环Nr-1轮加密运算 */
    for (round = 1; round < Nr; round++)
    {
        /* 2.字节代换 */
        aes_SubBytes(ciphertext, 1);

        /* 3.行移位 */
        aes_ShiftRows(ciphertext);

        /* 4.列混合 */
        aes_MixColums(ciphertext);

        /* 5.加轮密钥 */
        aes_Addroundkey(ciphertext, expanded_key, round);
    }

    /* 6.最后一轮(字节代换，行移位，加轮密钥) */
    aes_SubBytes(ciphertext, 1);
    aes_ShiftRows(ciphertext);
    aes_Addroundkey(ciphertext, expanded_key, round);
#endif
}

/* 数据解密 */
void aes_DecryptState(uint8_t *ciphertext, uint8_t *expanded_key, uint8_t *plaintext)
{
    uint8_t round = 0;
    memcpy(plaintext, ciphertext, 16);
#ifdef test_Decrypt
    /* 1.初始轮密钥加法 */
    aes_Addroundkey(plaintext, expanded_key, Nr);
    print_state(plaintext);
    printf("\n");
    /* 循环Nr-1轮解密运算 */
    for (round = Nr - 1; round > 0; round--)
    {
        /* 2.行逆移位 */
        aes_InvShiftRows(plaintext);
        print_state(plaintext);
        printf("\n");
        /* 3.字节逆代换 */
        aes_SubBytes(plaintext, 0);
        print_state(plaintext);
        printf("\n");
        /* 4.加轮密钥 */
        aes_Addroundkey(plaintext, expanded_key, round);
        print_state(plaintext);
        printf("\n");
        /* 5.列逆混合 */
        aes_InvMixColums(plaintext);
        print_state(plaintext);
        printf("\n");
    }

    /* 6.最后一轮(行逆移位，字节逆代换，加轮密钥) */
    aes_InvShiftRows(plaintext);
    print_state(plaintext);
    printf("\n");
    aes_SubBytes(plaintext, 0);
    print_state(plaintext);
    printf("\n");
    aes_Addroundkey(plaintext, expanded_key, 0);
    print_state(plaintext);
    printf("\n");
#else
    aes_Addroundkey(plaintext, expanded_key, Nr);
    /* 循环Nr-1轮解密运算 */
    for (round = Nr - 1; round > 0; round--)
    {
        /* 2.行逆移位 */
        aes_InvShiftRows(plaintext);

        /* 3.字节逆代换 */
        aes_SubBytes(plaintext, 0);

        /* 4.加轮密钥 */
        aes_Addroundkey(plaintext, expanded_key, round);

        /* 5.列逆混合 */
        aes_InvMixColums(plaintext);
    }

    /* 6.最后一轮(行逆移位，字节逆代换，加轮密钥) */
    aes_InvShiftRows(plaintext);
    aes_SubBytes(plaintext, 0);
    aes_Addroundkey(plaintext, expanded_key, 0);
#endif
}

/* CMAC算法实现 */
void xor_block(uint8_t *a, const uint8_t *b)
{
    for (int i = 0; i < BLOCK_SIZE; ++i)
    {
        a[i] = a[i]^b[i];
    }
}

// 填充移位,低位填充0
void shift_left(uint8_t *m){
    uint8_t bit_tmp;
    for(int i = 0;i<BLOCK_SIZE;i++)
    {
        if(i == BLOCK_SIZE - 1) bit_tmp = 0;
        else bit_tmp = m[i+1]>>7;
        m[i] = (m[i]<<1) | bit_tmp;
    }
}

/* 子密钥的生成 */
void generate_subkeys(uint8_t *key, uint8_t *k1, uint8_t *k2)
{
    uint8_t l[BLOCK_SIZE] = {0};
    aes_EncryptState(l, key, l); // l = AES-ECB(0^128)
#ifdef test_CMAC
    printf("l: \n");
    print_state(l);
#endif
    memcpy(k1, l, BLOCK_SIZE);
    shift_left(k1);
    if (l[0] & 0x80)
    {
        k1[BLOCK_SIZE - 1] ^= Rb;
    }
    memcpy(k2, k1, BLOCK_SIZE);
    shift_left(k2);
    if (k1[0] & 0x80)
    {
        k2[BLOCK_SIZE - 1] ^= Rb;
    }
}

/* hex数组转bin数组 */
void hexToBinary(uint8_t* hexArray, size_t hexLength, uint8_t* binaryArray) 
{
    // 将十六进制数组转换为二进制数组
    size_t index = 0;
     size_t bitLength = 8*hexLength;
    for (size_t i = 0; i < hexLength; i++) {
        uint8_t hex = hexArray[i];
        for (int j = 7; j >= 0; j--) {
            if (index >= bitLength) {
                // 超出有效位长
                return;
            }
            binaryArray[index++] = (hex >> j) & 0x01;
        }
    }
}

// bit数组填充
void BinPadding(uint8_t *m, uint8_t ls_step,uint16_t len)
{
    uint8_t ms[len];
    memcpy(ms,m+ls_step,len);
    memcpy(m,ms,len);
}

// 确定byte的最高有效位距离最高位长度
uint8_t get_bits(uint8_t in) {
    uint8_t i = 0x80;
    uint8_t index = 0;
    while (!(in & i))
    {
        i >>= 1;
        index++;
    }
    return index;
}

/* 计算bit数 */
uint8_t Bytes_Len(uint8_t *message)
{
    uint8_t len = 8;
    int i = 0;
    for (; i < BLOCK_SIZE; i++)
    {
        if (message[i])
        {
            uint8_t tmp = 0x80;
            while (!(message[i] & tmp))
            {
                tmp >>= 1;
                len--;
            }
            len += 8 * (15 - i);
            break;
        }
    }
    return len;
}

/* bin数组转hex数组 */
void binaryToHex(uint8_t* binaryArray, size_t binaryLength, uint8_t* hexArray) {
    // 计算十六进制数组长度
    size_t hexLength = (binaryLength + 7) / 8;

    // 将二进制数组转换为十六进制数组
    size_t hexIndex = 0;
    uint8_t hexByte = 0;
    size_t bitIndex = 0;
    for (size_t i = 0; i < binaryLength; i++) {
        uint8_t bit = binaryArray[i];
        hexByte |= (bit << (7 - bitIndex));
        bitIndex++;
        if (bitIndex == 8 || i == binaryLength - 1) {
            hexArray[hexIndex++] = hexByte;
            hexByte = 0;
            bitIndex = 0;
        }
    }
}

/* 3格hex数组串联，bin数组输出 */
void hexConcat(uint8_t* hexArray1, uint8_t* hexArray2, uint8_t* hexArray3,uint8_t* resultArray) 
{
    // 将三个十六进制数组转换为二进制数组并按有效位拼接
    size_t binaryLength1, binaryLength2, binaryLength3;//二进制长度
    uint8_t hexLength1,hexLength2,hexLength3;          //十六进制长度

    //计算有效bit数(不等于有效byte数)
    binaryLength1 = Bytes_Len(hexArray1);
    binaryLength2 = Bytes_Len(hexArray2);
    binaryLength3 = Bytes_Len(hexArray3);

    //计算有效byte数
    hexLength1 = (binaryLength1 + 7) / 8;
    hexLength2 = (binaryLength2 + 7) / 8;
    hexLength3 = (binaryLength3 + 7) / 8;

    //计算有效byte位置
    uint8_t hex1_st,hex2_st,hex3_st;
    hex1_st = 0;hex2_st = 0;hex3_st = 0;
    while(!hexArray1[hex1_st++]);
    while(!hexArray2[hex2_st++]);
    while(!hexArray3[hex3_st++]);

    uint8_t binaryArray1[hexLength1*8];
    uint8_t binaryArray2[hexLength2*8];
    uint8_t binaryArray3[hexLength3*8];
    memset(binaryArray1, 0, hexLength1*8);
    memset(binaryArray2, 0, hexLength2*8);
    memset(binaryArray3, 0, hexLength3*8);

    hexToBinary(hexArray1 + hex1_st - 1, BLOCK_SIZE - hex1_st + 1, binaryArray1);
    // for(int i = 0;i<hexLength1*8;i++){
    //     printf("%d ",binaryArray1[i]);
    // }
    // printf("\n\n");
    BinPadding(binaryArray1,get_bits(hexArray1[hex1_st - 1]),binaryLength1);
    // for(int i = 0;i<binaryLength1;i++){
    //     printf("%d ",binaryArray1[i]);
    // }
    // printf("\n\n");
    hexToBinary(hexArray2 + hex2_st - 1, BLOCK_SIZE - hex2_st + 1, binaryArray2);
    // for(int i = 0;i<hexLength2*8;i++){
    //     printf("%d ",binaryArray2[i]);
    // }
    // printf("\n\n");
    BinPadding(binaryArray2,get_bits(hexArray2[hex2_st - 1]),binaryLength2);
    // for(int i = 0;i<binaryLength2;i++){
    //     printf("%d ",binaryArray2[i]);
    // }
    // printf("\n\n");
    hexToBinary(hexArray3 + hex3_st - 1, BLOCK_SIZE - hex3_st + 1, binaryArray3);
    // for(int i = 0;i<hexLength3*8;i++){
    //     printf("%d ",binaryArray3[i]);
    // }
    // printf("\n\n");
    BinPadding(binaryArray3,get_bits(hexArray3[hex3_st - 1]),binaryLength3);
    // for(int i = 0;i<binaryLength3;i++){
    //     printf("%d ",binaryArray3[i]);
    // }
    // printf("\n\n");

    // 将三个二进制数组串联起来
    size_t resultIndex = 0;
    for (size_t i = 0; i < binaryLength1; i++) {
        resultArray[resultIndex++] = binaryArray1[i];
    }
    for (size_t i = 0; i < binaryLength2; i++) {
        resultArray[resultIndex++] = binaryArray2[i];
    }
    for (size_t i = 0; i < binaryLength3; i++) {
        resultArray[resultIndex++] = binaryArray3[i];
    }
    if((binaryLength1+binaryLength2+binaryLength3) % 128){
        resultArray[resultIndex++] = 1;
    }
    for(size_t i = 0;i<3*BLOCK_SIZE;i++)
    {
        resultArray[resultIndex++] = 0;
    }
}

/* CMAC的生成 */
void aes_CMAC(uint8_t *message, uint8_t *key, uint8_t *mac)
{
    uint8_t k1[BLOCK_SIZE], k2[BLOCK_SIZE];
    generate_subkeys(key, k1, k2);

#ifdef test_CMAC
    printf("k1: \n");
    print_state(k1);
    printf("k2: \n");
    print_state(k2);
#endif

    // 三个消息缓存
    uint8_t blocks[3][BLOCK_SIZE];
    memcpy(blocks[0], message, BLOCK_SIZE);
    memcpy(blocks[1], &message[BLOCK_SIZE], BLOCK_SIZE);
    memcpy(blocks[2], &message[BLOCK_SIZE * 2], BLOCK_SIZE);
    uint16_t M_len = Bytes_Len(blocks[0])+ Bytes_Len(blocks[1])+ Bytes_Len(blocks[2]);

#ifdef test_CMAC
    printf("M1_len: %d ;M1_len: %d ;M1_len: %d ;M_len: %d\n",Bytes_Len(blocks[0]),Bytes_Len(blocks[1]),Bytes_Len(blocks[2]),M_len);
#endif  

    // 串联输出二进制数组
    uint8_t binCat[24 * BLOCK_SIZE];
    hexConcat(blocks[0],blocks[1],blocks[2],binCat);

#ifdef test_CMAC
    printf("binConcat:\n");
    for(int i = 0;i<24 * BLOCK_SIZE;i++){
        printf("%d ",binCat[i]);
    }
    printf("\n\n");
#endif

    // 填充并分段输出
    uint8_t hexCat[48];
    binaryToHex(binCat,384,hexCat);

#ifdef test_CMAC
    printf("hexConcat:\n");
    for(int i=0;i<48;i++){
        printf("%02x ",hexCat[i]);
    }
    printf("\n\n");
#endif

    // 填充并分段输出
    memcpy(blocks[0], hexCat, BLOCK_SIZE);
    memcpy(blocks[1], &hexCat[BLOCK_SIZE], BLOCK_SIZE);
    memcpy(blocks[2], &hexCat[BLOCK_SIZE * 2], BLOCK_SIZE);

#ifdef test_CMAC
    printf("M1_out:\n");print_state(blocks[0]);
    printf("M2_out:\n");print_state(blocks[1]);
    printf("M3_out:\n");print_state(blocks[2]);
#endif

    uint8_t M1_tmp[BLOCK_SIZE],M2_tmp[BLOCK_SIZE],M3_tmp[BLOCK_SIZE];
    if(M_len <= 128) //一块
    {   
        if(M_len == 128)
            xor_block(blocks[0],k1);
        else 
            xor_block(blocks[0],k2);
        aes_EncryptState(blocks[0], key,M1_tmp);
        memcpy(mac,M1_tmp,BLOCK_SIZE);
#ifdef test_CMAC
        print_state(M1_tmp);
        printf("\n");
#endif
    }
    else if(M_len>128 && M_len <=256) //两块
    {
        aes_EncryptState(blocks[0], key,M1_tmp);
#ifdef test_CMAC
        print_state(M1_tmp);
        printf("\n");
#endif
        if(M_len == 256)
            xor_block(blocks[1],k1);
        else
            xor_block(blocks[1],k2);
        xor_block(M1_tmp,blocks[1]);
        aes_EncryptState(M1_tmp, key,M2_tmp);
        memcpy(mac,M2_tmp,BLOCK_SIZE);
#ifdef test_CMAC
        print_state(M2_tmp);
        printf("\n");
#endif
    }
    else if(M_len > 256 && M_len <= 384) // 三块
    {
        aes_EncryptState(blocks[0], key,M1_tmp);
#ifdef test_CMAC
        print_state(M1_tmp);
        printf("\n");
#endif
        xor_block(M1_tmp,blocks[1]);
        aes_EncryptState(M1_tmp,key,M2_tmp);
#ifdef test_CMAC
        print_state(M2_tmp);
        printf("\n");
#endif
        xor_block(M2_tmp,blocks[2]);
        if(M_len == 384)
            xor_block(M2_tmp,k1);
        else
            xor_block(M2_tmp,k2);
        aes_EncryptState(M2_tmp,key,M3_tmp);
        memcpy(mac,M3_tmp,BLOCK_SIZE);
#ifdef test_CMAC
        print_state(M3_tmp);
        printf("\n");
#endif
    }
}


/* 测试 
    0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
    0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
    0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
    0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

*/
void test()
{
    uint8_t plaintext[16] = {0x89, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                             0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}; /*自定义明文*/
    uint8_t key[32] = {0x89, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                       0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                       0x00, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                       0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf0}; /*自定义密钥*/
    printf("key_in:4B 45 59 ");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x ", key[i]);
    }
    printf("\n");
    printf("msga:4D 53 47 41 ");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", plaintext[i]);
    }
    printf("\n");

    uint8_t msg[3 * BLOCK_SIZE];
    uint8_t cmac[BLOCK_SIZE];
    uint8_t expanded_key[240];
    uint8_t ciphertext[16];  /*加密后的密文*/
    uint8_t decrypttext[16]; /*解密后的明文*/
    for (int i = 0; i < BLOCK_SIZE; i++)
    {
        msg[i] = plaintext[i];
    }
    for (int i = BLOCK_SIZE; i < 3 * BLOCK_SIZE; i++)
    {
        msg[i] = key[i - BLOCK_SIZE];
    }
    printf("msgb:4D 53 47 42 ");
    for (int i = 0; i < 48; i++)
    {
        printf("%02x ", msg[i]);
    }
    printf("\n");
#if 0
	int i, j;
	print_state(plaintext);
	printf("\n");
	aes_ShiftRows(plaintext);
	print_state(plaintext);
	printf("\n");
	aes_InvShiftRows(plaintext);
	print_state(plaintext);
#endif // 行移位测试
#if 0
	int i, j;
	aes_MixColums(plaintext);
	print_state(plaintext);
	printf("\n");
	aes_InvMixColums(plaintext);
	print_state(plaintext);
#endif // 列混合测试
#if 0
    uint8_t expanded_key[240];
    // 调用密钥扩展函数生成扩展密钥
    aes_Keyexpansion(key, expanded_key);
    //打印扩展密钥
    printf("Expanded Key:\n");
    for (int i = 0; i < Nb * (Nr + 1) * 4; i++)
    {
        printf("0x%02x ", expanded_key[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
#endif // 密钥扩展测试
#if 1
    aes_Keyexpansion(key, expanded_key);
    aes_EncryptState(plaintext, expanded_key, ciphertext);
    printf("ciper:\n");
    print_state(ciphertext);
    aes_DecryptState(ciphertext, expanded_key, decrypttext);
    printf("decrypt:\n");
    print_state(decrypttext);
#endif // AES加解密测试
#if 1
    aes_Keyexpansion(key, expanded_key);
    aes_CMAC(msg,expanded_key,cmac);

    printf("CMAC: ");
    printf("\n");
    print_state(cmac);
    printf("\n");
#endif // AES-CMAC论证
}