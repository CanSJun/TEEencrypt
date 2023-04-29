/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

struct ta_attrs {
	TEEC_Context ctx;
	TEEC_Session sess;
};

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;

	char plaintext[1024] = { 0, };
	int len = 1024;
	char buffer[1024] = { 0, };
	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));


	if (!strcmp(argv[3], "Ceaser")) {

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
			TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = plaintext;
		op.params[0].tmpref.size = len;
		op.params[1].value.a = 0;

		if (!strcmp(argv[1], "-e")) {

			printf("===Encryption===\n");

			FILE* f = fopen(argv[2], "r");
			if (f == NULL) {
				printf("%s not found \n", argv[2]);
				return 1;
			}

			fgets(plaintext, sizeof(plaintext), f);
			fclose(f);
			printf("===PlainText===\n%s\n", plaintext);
			memcpy(op.params[0].tmpref.buffer, plaintext, len);

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
					res, err_origin);



			memcpy(buffer, op.params[0].tmpref.buffer, len);
			printf("Encrypted : %s\n", buffer);
			printf("Key : %d \n", op.params[1].value.a);

			//File output
			f = fopen("ciphertext_key.txt", "w+");
			fwrite(plaintext, strlen(plaintext), 1, f); // plain_txt
			fprintf(f, "%d", op.params[1].value.a); // key 
			fclose(f);
		}
		else if (!strcmp(argv[1], "-d")) {
			FILE* f;
			char key[1024] = { 0, };
			printf("===Decryption===\n");
			f = fopen(argv[2], "r");
			if (f == NULL) {
				printf("%s not found", argv[2]);
				return 1;
			}
			fgets(buffer, sizeof(buffer), f);
			fgets(key, sizeof(key), f);
			fclose(f);

			memcpy(op.params[0].tmpref.buffer, buffer, len);
			int c_key = atoi(key);
			op.params[1].value.a = c_key;

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
					res, err_origin);

			memcpy(plaintext, op.params[0].tmpref.buffer, len);
			printf("Decrypted : %s \n", plaintext);
			printf("Key : %d \n", op.params[1].value.a);

			//file output
			f = fopen("plain.txt", "w+");
			fwrite(plaintext, strlen(plaintext), 1, f); // plain_txt , Nope key
			fclose(f);
		}
		else {
			printf("[2]Invalid argument %s \n", argv[2]);
			return 1;
		}

	}
	else if (!strcmp(argv[3], "RSA")) {
		char RSAplaintext[1024] = { 0, };
		char RSAbuffer[1024] = { 0, };
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
			TEEC_MEMREF_TEMP_OUTPUT,
			TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = RSAplaintext;
		op.params[0].tmpref.size = RSA_MAX_PLAIN_LEN_1024;
		op.params[1].tmpref.buffer = RSAbuffer;
		op.params[1].tmpref.size = RSA_CIPHER_LEN_1024;

		res = TEEC_InvokeCommand(&sess, TA_RSA_CMD_GENKEYS, NULL, NULL);
		if (res != TEEC_SUCCESS)
			errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_GENKEYS) failed %#x\n", res);
		printf("\n=========== Keys already generated. ==========\n");

		if (!strcmp(argv[1], "-e")) {

			printf("===RSA Encryption===\n");

			FILE* f = fopen(argv[2], "r");
			if (f == NULL) {
				printf("%s not found \n", argv[2]);
				return 1;
			}

			fgets(RSAplaintext, sizeof(RSAplaintext), f);
			fclose(f);
			res = TEEC_InvokeCommand(&sess, TA_RSA_CMD_ENCRYPT, &op, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_ENCRYPT) failed %#x\n", res);

			printf("RSA Encrypted : %s\n", RSAbuffer);

			//File output
			f = fopen("RSA_result.txt", "w+");
			fwrite(RSAbuffer, strlen(RSAbuffer), 1, f); // plain_txt
			fclose(f);
		}
		else {
			printf("[2]Invalid argument %s \n", argv[2]);
			return 1;
		}

	}else{
	printf("[3]Invalid argument %s \n", argv[3]);
	return 1;
	}
	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);
	return 0;
}
