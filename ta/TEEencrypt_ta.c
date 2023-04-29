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

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <stdlib.h>
#include <TEEencrypt_ta.h>
#include <ctype.h>
#define root_key 177

#define RSA_KEY_SIZE 1024
#define MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

struct rsa_session {
	TEE_OperationHandle op_handle;	/* RSA operation */
	TEE_ObjectHandle key_handle; /* Key handle */
};

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}


TEE_Result check_params(uint32_t param_types) {
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	return TEE_SUCCESS;
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
//	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */

	struct rsa_session* sess;
	sess = TEE_Malloc(sizeof(*sess), 0);
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;

	*sess_ctx = (void*)sess;
	DMSG("\nSession %p: newly allocated\n", *sess_ctx);

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */

	struct rsa_session* sess;

	/* Get ciphering context from session ID */
	DMSG("Session %p: release session", sess);
	sess = (struct rsa_session*)sess_ctx;

	/* Release the session resources
	   These tests are mandatories to avoid PANIC TA (TEE_HANDLE_NULL) */
	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);
	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);
	TEE_Free(sess);

	IMSG("Goodbye!\n");
}

TEE_Result RSA_create_key_pair(void* session) {
	TEE_Result ret;
	size_t key_size = RSA_KEY_SIZE;
	struct rsa_session* sess = (struct rsa_session*)session;

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc transient object handle: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Transient object allocated. ==========\n");

	ret = TEE_GenerateKey(sess->key_handle, key_size, (TEE_Attribute*)NULL, 0);
	if (ret != TEE_SUCCESS) {
		EMSG("\nGenerate key failure: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Keys generated. ==========\n");
	return ret;
}

TEE_Result prepare_rsa_operation(TEE_OperationHandle* handle, uint32_t alg, TEE_OperationMode mode, TEE_ObjectHandle key) {
	TEE_Result ret = TEE_SUCCESS;
	TEE_ObjectInfo key_info;
	
	ret = TEE_GetObjectInfo1(key, &key_info);
	DMSG("TEST INPUT - 0\n");
	if (ret != TEE_SUCCESS) {
		EMSG("\nTEE_GetObjectInfo1: %#\n" PRIx32, ret);
		return ret;
	}
	DMSG("TEST INPUT - 1\n");
	ret = TEE_AllocateOperation(handle, alg, mode, key_info.keySize);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc operation handle : 0x%x\n", ret);
		return ret;
	}
	DMSG("TEST INPUT - 2\n");
	DMSG("\n========== Operation allocated successfully. ==========\n");

	ret = TEE_SetOperationKey(*handle, key);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to set key : 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Operation key already set. ==========\n");

	return ret;

}
TEE_Result RSA_encrypt(void* session, uint32_t param_types, TEE_Param params[4]) {
	TEE_Result ret;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	struct rsa_session* sess = (struct rsa_session*)session;

	if (check_params(param_types) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	void* plain_txt = params[0].memref.buffer;
	size_t plain_len = params[0].memref.size;
	void* cipher = params[1].memref.buffer;
	size_t cipher_len = params[1].memref.size;

	DMSG("\n========== Preparing encryption operation ==========\n");
	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_ENCRYPT, sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to prepare RSA operation: 0x%x\n", ret);
		goto err;
	}

	DMSG("\nData to encrypt: %s\n", (char*)plain_txt);
	ret = TEE_AsymmetricEncrypt(sess->op_handle, (TEE_Attribute*)NULL, 0,
		plain_txt, plain_len, cipher, &cipher_len);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to encrypt the passed buffer: 0x%x\n", ret);
		goto err;
	}
	DMSG("\nEncrypted data: %s\n", (char*)cipher);
	DMSG("\n========== Encryption successfully ==========\n");
	return ret;

err:
	TEE_FreeOperation(sess->op_handle);
	TEE_FreeOperation(sess->key_handle);
	return ret;
}

TEE_Result RSA_decrypt(void* session, uint32_t param_types, TEE_Param params[4]) {
	TEE_Result ret;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	struct rsa_session* sess = (struct rsa_session*)session;

	if (check_params(param_types) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	void* plain_txt = params[1].memref.buffer;
	size_t plain_len = params[1].memref.size;
	void* cipher = params[0].memref.buffer;
	size_t cipher_len = params[0].memref.size;

	DMSG("\n========== Preparing decryption operation ==========\n");
	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_DECRYPT, sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to prepare RSA operation: 0x%x\n", ret);
		goto err;
	}

	DMSG("\nData to decrypt: %s\n", (char*)cipher);
	ret = TEE_AsymmetricDecrypt(sess->op_handle, (TEE_Attribute*)NULL, 0,
		cipher, cipher_len, plain_txt, &plain_len);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to decrypt the passed buffer: 0x%x\n", ret);
		goto err;
	}
	DMSG("\nDecrypted data: %s\n", (char*)plain_txt);
	DMSG("\n========== Decryption successfully ==========\n");
	return ret;

err:
	TEE_FreeOperation(sess->op_handle);
	TEE_FreeTransientObject(sess->key_handle);
	return ret;
}

static TEE_Result enc_value(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_VALUE_INOUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) return TEE_ERROR_BAD_PARAMETERS;

	DMSG("ENC CALLED");

	char* str = (char *)params[0].memref.buffer;
	int len = strlen(params[0].memref.buffer);
	int ran_num = 0;
	char en[1024] = { 0, };

	TEE_GenerateRandom(&ran_num, sizeof(ran_num));
	ran_num =  abs(ran_num) % 26 + 1; // 1 ~ 26 사이 값을 가지게

	DMSG("[ENC]BEFORE >> %s", str);
	DMSG("[ENC]KEY >> %d", ran_num);
	memcpy(en, str, len);

	for (int i = 0; i < len; i++) {
		if (isalpha(en[i])) {
			if (islower(en[i])) {
				en[i] = ((en[i] - 'a' + ran_num) % 26) + 'a';
			}
			else {
				en[i] = ((en[i] - 'A' + ran_num) % 26) + 'A';
			}
		}
	}
	memcpy(str, en, len);
	/*
만약에 ran_num이 7으로 받았다고하고 str[i]가 A라면
str[i] -= 65를 통해 str[i] 가 0이 됨 그 이후 ran_num 7을 더하고
%26으로 나누어도 7이니깐. 그 후 65 + 7를 해주어서 72가 되니
72는 H가 되니깐 A -> H로 치환이 된것이다.
*/
	DMSG("[ENC]AFTER >> %s ", str);
	params[1].value.a = ran_num + root_key; // 랜덤키를 저장하는대 이때 루트키와 같이 저장
	DMSG("[ENC]KEY >> %d ", params[1].value.a);
	return TEE_SUCCESS;
}

static TEE_Result dec_value(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_VALUE_INOUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) return TEE_ERROR_BAD_PARAMETERS;
	DMSG("DEC CALLED");

	char* str =(char*)params[0].memref.buffer;
	int len = strlen(params[0].memref.buffer);
	int key = params[1].value.a - root_key; // 루트키를 뺀 결과를 가져 온다.
	char dn[1024] = { 0, };
	DMSG("[DEC]BEFORE >> %s", str);

	memcpy(dn, str, len);
	
	for (int i = 0; i < len; i++) {
		if (isalpha(dn[i])) {
			if (islower(dn[i])) {
				dn[i] = ((dn[i] - 'a' - key + 26) % 26) + 'a';
			}
			else {
				dn[i] = ((dn[i] - 'A' - key + 26) % 26) + 'A';
			}
		}
	}
	memcpy(str, dn, len);
	/*
	아까랑 이어서 생각하면 H가 들어옴 그러면 72가 들어오는대 여기서 65를 빼주자 그러면 7이 남음
	그 다음에 우리가 불러왔던 10키에서 root key를 뺀 결과가 7이니깐 0이 됨. 여기서 %26로 나머지값을 계산을 해준다
	할떄도 했으니깐, 그러면 0 % 26은 어짜피 0이니깐 0에서 + 65가 더해져서 A가 된다. 그러면 A -> H간게 H -> A로 돌아온다.
	그러면 26을
	*/

	DMSG("[DEC]AFTER >> %s", str);
	return TEE_SUCCESS;
}
/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_TEEencrypt_CMD_ENC_VALUE:
		return enc_value(param_types, params);
	case TA_TEEencrypt_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	case TA_TEEencrypt_CMD_RANDOMKEY_GET:
		return dec_value(param_types, params);
	case TA_TEEencrypt_CMD_RANDOMKEY_ENC:
		return dec_value(param_types, params);
	case TA_RSA_CMD_GENKEYS:
		return RSA_create_key_pair(sess_ctx);
	case TA_RSA_CMD_ENCRYPT:
		return RSA_encrypt(sess_ctx, param_types, params);
	case TA_RSA_CMD_DECRYPT:
		return RSA_decrypt(sess_ctx, param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
