/*
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2013, Anthony Minessale II <anthm@freeswitch.org>
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * The Initial Developer of the Original Code is
 * Anthony Minessale II <anthm@freeswitch.org>
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Brian West <brian@freeswitch.org>
 * Christopher Rienzo <chris.rienzo@grasshopper.com>
 *
 * mod_aliasr - aliyun STT Interface
 *
 *
 */

#include <switch.h>
#include <switch_curl.h>
#include <switch_utils.h>
#include <switch_apr.h>
#include <switch_json.h>
#include "openssl/hmac.h"
#include "openssl/ssl.h"
#include "aliNlsDef.h"
#include "wsclient.h"
#include "switch_regex.h"
#include "fspr_arch_utf8.h"

#define die(...) switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, __VA_ARGS__); goto error

SWITCH_MODULE_LOAD_FUNCTION(mod_aliasr_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_aliasr_shutdown);
SWITCH_MODULE_DEFINITION(mod_aliasr, mod_aliasr_load, mod_aliasr_shutdown, NULL);

static switch_mutex_t *MUTEX = NULL;
static switch_event_node_t *NODE = NULL;

#define ALIYUN_BLOCK_SIZE 4800
// #define FRAME_16K_20MS 640
// #define FRAME_16K_100MS 3200
// #define FRAME_8K_20MS 320
// #define SAMPLE_RATE_8K 8000
// #define SAMPLE_RATE_16K 16000

#define URL_SIZE 1024
#define HEADER_UUID_LENGTH 32

typedef struct {
	char host[URL_SIZE];
	int port;
	char protocal[10];
	char path[URL_SIZE];
	switch_bool_t secure;
} url_t;

typedef struct {
	char *file;
	char *location;
	char *content;
	cJSON *root;
	cJSON *name;
	cJSON *result;
	int32_t score;
	int32_t confidence;
	switch_buffer_t *text_result;
	switch_mutex_t *mutex;
} grammar_t;

static struct {
	//char *dictionary;
	//char *language_weight;
	uint32_t thresh;
	int no_input_timeout;
	int speech_timeout;
	int speech_pausetime;
	switch_bool_t start_input_timers;
	int confidence_threshold;
	//uint32_t silence_hits;
	uint32_t listen_hits;
	int recognition_cliptime;
	//int auto_reload;
	char* app_key;
	char* access_key_id;
	char* access_key_secret;
	char* api_url;
	switch_bool_t api_secure;
	struct addrinfo *api_ips;
	char* api_host;
	char* api_path;
	int api_port;
	char* token_url;
	char* token_path;
	char* token_cache_pathfile;
	char token_id[64];
	int token_expire_time;
	SSL_CTX *ssl_ctx;
	switch_memory_pool_t *pool;
} globals;

typedef enum {
	PSFLAG_HAS_TEXT = (1 << 0),
	PSFLAG_READY = (1 << 1),
	PSFLAG_BARGE = (1 << 2),
	PSFLAG_ALLOCATED = (1 << 3),
	PSFLAG_INPUT_TIMERS = (1 << 4),
	PSFLAG_START_OF_SPEECH = (1 << 5),
	PSFLAG_NOINPUT_TIMEOUT = (1 << 6),
	PSFLAG_SPEECH_TIMEOUT = (1 << 7),
	PSFLAG_NOINPUT = (1 << 8),
	PSFLAG_NOMATCH = (1 << 9),
	PSFLAG_ASRSTOP = (1 << 10)
} psflag_t;

typedef struct {
	uint32_t flags;
	switch_mutex_t *flag_mutex;
	//uint32_t org_silence_hits;
	uint32_t thresh;
	//uint32_t silence_hits;
	uint32_t listen_hits;
	uint32_t listening;
	//uint32_t countdown;
	int no_input_timeout;
	int speech_timeout;
	int speech_pausetime;
	switch_bool_t start_input_timers;
	switch_time_t pause_silence_time;
	switch_time_t timeout_silence_time;
	int confidence_threshold;
	grammar_t grammar;
	switch_buffer_t *text_result;
	int32_t score;
	int32_t confidence;
	int recognition_cliptime;
	switch_buffer_t *audio_buffer;
	switch_queue_t *recognition_queue;
	switch_thread_t *recognition_thread;
	char task_id[HEADER_UUID_LENGTH + 1];
	wsh_t wsh;
} ali_nls_t;

#ifndef WSS_STANDALONE

void init_ssl(void)
{
	SSL_library_init();
	SSL_load_error_strings();
	globals.ssl_ctx = SSL_CTX_new(SSLv23_client_method());//                        CHK_NULL(ctx);

	SSL_CTX_set_mode(globals.ssl_ctx,
		SSL_MODE_ENABLE_PARTIAL_WRITE |
		SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
		SSL_MODE_AUTO_RETRY);
	assert(globals.ssl_ctx);
}
void deinit_ssl(void)
{
	SSL_CTX_free(globals.ssl_ctx);
	globals.ssl_ctx = NULL;

	return;
}

#else
static unsigned long pthreads_thread_id(void);
static void pthreads_locking_callback(int mode, int type, const char *file, int line);

static pthread_mutex_t *lock_cs;
static long *lock_count;



static void thread_setup(void)
{
	int i;

	lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));

	for (i = 0; i < CRYPTO_num_locks(); i++) {
		lock_count[i] = 0;
		pthread_mutex_init(&(lock_cs[i]), NULL);
	}

	CRYPTO_set_id_callback(pthreads_thread_id);
	CRYPTO_set_locking_callback(pthreads_locking_callback);
}

static void thread_cleanup(void)
{
	int i;

	CRYPTO_set_locking_callback(NULL);

	for (i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_destroy(&(lock_cs[i]));
	}
	OPENSSL_free(lock_cs);
	OPENSSL_free(lock_count);

}

static void pthreads_locking_callback(int mode, int type, const char *file, int line)
{

	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&(lock_cs[type]));
		lock_count[type]++;
	}
	else {
		pthread_mutex_unlock(&(lock_cs[type]));
	}
}



static unsigned long pthreads_thread_id(void)
{
	return (unsigned long)pthread_self();
}


void init_ssl(void) {
	SSL_library_init();


	OpenSSL_add_all_algorithms();   /* load & register cryptos */
	SSL_load_error_strings();     /* load all error messages */
	ws_globals.ssl_method = SSLv23_server_method();   /* create server instance */
	ws_globals.ssl_ctx = SSL_CTX_new(ws_globals.ssl_method);         /* create context */
	assert(ws_globals.ssl_ctx);

	/* Disable SSLv2 */
	SSL_CTX_set_options(ws_globals.ssl_ctx, SSL_OP_NO_SSLv2);
	/* Disable SSLv3 */
	SSL_CTX_set_options(ws_globals.ssl_ctx, SSL_OP_NO_SSLv3);
	/* Disable TLSv1 */
	SSL_CTX_set_options(ws_globals.ssl_ctx, SSL_OP_NO_TLSv1);
	/* Disable Compression CRIME (Compression Ratio Info-leak Made Easy) */
	SSL_CTX_set_options(ws_globals.ssl_ctx, SSL_OP_NO_COMPRESSION);
	/* set the local certificate from CertFile */
	SSL_CTX_use_certificate_file(ws_globals.ssl_ctx, ws_globals.cert, SSL_FILETYPE_PEM);
	/* set the private key from KeyFile */
	SSL_CTX_use_PrivateKey_file(ws_globals.ssl_ctx, ws_globals.key, SSL_FILETYPE_PEM);
	/* verify private key */
	if (!SSL_CTX_check_private_key(ws_globals.ssl_ctx)) {
		abort();
	}

	SSL_CTX_set_cipher_list(ws_globals.ssl_ctx, "HIGH:!DSS:!aNULL@STRENGTH");

	thread_setup();
}


void deinit_ssl(void) {
	thread_cleanup();
}

#endif

void alinls_gen_uuid(char *buffer, int size)
{
	switch_uuid_t uuid;
	switch_uuid_get(&uuid);
	const unsigned char *d = uuid.data;

	snprintf(buffer, size,
		"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
		d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]);
}

static int error_code() {
#ifdef _MSC_VER
	return (WSAGetLastError());
#else
	return errno;
#endif
}

static void close_file(ws_socket_t *sock)
{
	if (*sock != ws_sock_invalid) {
#ifndef WIN32
		close(*sock);
#else
		closesocket(*sock);
#endif
		*sock = ws_sock_invalid;
	}
}

//static size_t header_write_callback(void *ptr, size_t size, size_t nmemb, void *userp)
//{
//	ali_t *ali = (ali_t *)userp;
//
//	if (switch_stristr("Content-Length", (const char*)ptr)) {
//		const char* pos = switch_stristr(":", (const char*)ptr);
//		if (pos) {
//			pos++;
//			ali->content_len = atoi(pos);
//		}
//	}
//
//	return size*nmemb;
//}

static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userp)
{
	switch_buffer_t *response = (switch_buffer_t *)userp;

	if (response) {
		switch_buffer_write(response, ptr, size * nmemb);
	}
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s\n", (char*)ptr);

	return size*nmemb;
}


static void disp_asr_result(cJSON * result)
{
	fspr_wchar_t *wvalue;
	fspr_size_t inchars, outchars;
	fspr_status_t status;

	outchars = inchars = strlen(result->valuestring) + 1;
	wvalue = malloc(outchars * sizeof(*wvalue));
	status = fspr_conv_utf8_to_ucs2(result->valuestring, &inchars, wvalue, &outchars);
	if (APR_SUCCESS == status) {
		outchars = inchars = strlen(result->valuestring) + 1;
		char *mbvalue = (char *)malloc(inchars * sizeof(char));
		WideCharToMultiByte(CP_ACP, 0, wvalue, inchars, mbvalue, outchars, NULL, NULL);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "text: [%s]\n", mbvalue);
		
		free((void *)mbvalue);
	}

// 	int len = MultiByteToWideChar(CP_UTF8, 0, result->valuestring, (int)strlen(result->valuestring), NULL, 0);
// 	wchar_t* wcs = (wchar_t*)malloc(sizeof(wchar_t) * len);
// 	char* sz = (char*)malloc(len * 2 + 1);
// 	memset(sz, 0, len * 2 + 1);
// 	MultiByteToWideChar(CP_UTF8, 0, result->valuestring, (int)strlen(result->valuestring), wcs, len);
// 	WideCharToMultiByte(54936, 0, wcs, len, sz, len * 2, NULL, NULL);
// 	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "text: [%s]\n", sz);
	free((void *)wvalue);
}

static switch_bool_t grammar_match_sentence(switch_asr_handle_t *ah, cJSON *sentence)
{
	ali_nls_t *ali = (ali_nls_t *)ah->private_info;
	cJSON *options = cJSON_GetObjectItem(ali->grammar.name, "options");
	if (options) { options = options->child; }
	if (!sentence  || !options) { return SWITCH_FALSE; }
	do {
		cJSON *text = cJSON_GetObjectItem(options, "text");
		cJSON *value = cJSON_GetObjectItem(options, "value");
		if (text && value && switch_stristr(text->valuestring, sentence->valuestring)){
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Matched: %s\n", value->valuestring);
			ali->grammar.result = value;
			switch_set_flag_locked(ali, PSFLAG_HAS_TEXT);
			return SWITCH_TRUE;
		}
	} while (options = options->next);

	return SWITCH_FALSE;
}

static void *SWITCH_THREAD_FUNC recognition_thread(switch_thread_t *thread, void *obj)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Recognition thread started.\n");

	switch_asr_handle_t *ah = (switch_asr_handle_t*)obj;
	ali_nls_t *ali = (ali_nls_t *)ah->private_info;
	switch_buffer_t *audio_buffer;
	uint8_t audio_data[ALIYUN_BLOCK_SIZE];
	int read_bytes;
	ws_opcode_t oc;
	uint8_t *response = NULL;

	while (!switch_test_flag(ali, PSFLAG_ASRSTOP)) {
		if (switch_queue_trypop(ali->recognition_queue, &audio_buffer) == SWITCH_STATUS_SUCCESS && audio_buffer) {
			//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Get audio from queue\n");
			switch_size_t len = switch_buffer_read(audio_buffer, audio_data, ALIYUN_BLOCK_SIZE);
			if (len > 0) {
				switch_size_t ret = ws_write_frame(&ali->wsh, WSOC_BINARY, audio_data, len);
				if (ret != len) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Send audio fail\n");
				}
				else {
					//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Send audio %d bytes\n", ret);
				}
			}
			switch_buffer_destroy(&audio_buffer);
			//switch_micro_sleep(20000);
			//continue;
		}

		response = NULL;
		oc = WSOC_CONTINUATION;
		//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ws_read_frame\n");
		read_bytes = ws_read_frame(&ali->wsh, &oc, &response);
		if (read_bytes > 0 && response) {
			//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s\n", response);
		
			cJSON *jason = cJSON_Parse(response);
			if (jason) {
				cJSON *header = cJSON_GetObjectItem(jason, "header");
				cJSON *payload = cJSON_GetObjectItem(jason, "payload");
				if (header) {
					cJSON *status = cJSON_GetObjectItem(header, "status");
					cJSON *name = cJSON_GetObjectItem(header, "name");
					cJSON *status_message = cJSON_GetObjectItem(header, "status_message");
					if (status && status->valueint == 20000000) {
						if (name && name->valuestring) {
							cJSON *session_id = NULL;
							cJSON *index = NULL;
							cJSON *time = NULL;
							cJSON *begin_time = NULL;
							cJSON *result = NULL;

							switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Event: %s\n", name->valuestring);
							
							if (payload) {
								session_id = cJSON_GetObjectItem(payload, "session_id");
								index = cJSON_GetObjectItem(payload, "index");
								time = cJSON_GetObjectItem(payload, "time");
								begin_time = cJSON_GetObjectItem(payload, "begin_time");
								result = cJSON_GetObjectItem(payload, "result");
							}

							if (!strcasecmp(name->valuestring, "TranscriptionStarted")) {
								//ali->wsh.block = 0;
								if (session_id && session_id->valuestring) {
									switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "session_id: %s\n", session_id->valuestring);
								}
							}
							else if (!strcasecmp(name->valuestring, "TranscriptionCompleted")) {
								
							}
							else if (!strcasecmp(name->valuestring, "SentenceBegin"))
							{
								if (index && time) {
									switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%d[%d]\n",
										index->valueint, time->valueint);
								}
							}
							else if (!strcasecmp(name->valuestring, "TranscriptionResultChanged"))
							{
								if (index && time && result) {
// 									switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%d[%d]: %s\n",
// 										index->valueint, time->valueint, result->valuestring);
									disp_asr_result(result);
								}
							}
							else if (!strcasecmp(name->valuestring, "SentenceEnd"))
							{
								if (index && time && result && begin_time) {
									// 									switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
									// "%d[%d,%d]:
									// %s\n", 										index->valueint, begin_time->valueint,
									// time->valueint, result->valuestring);
									disp_asr_result(result);

									// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ASR got new text:
									// [%s]\n", data->valuestring);
									grammar_match_sentence(ah, result);
									switch_buffer_write(ali->text_result, (void *)result->valuestring,
														strlen(result->valuestring));
								}
							}
							else {
								switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "ASR unknown event: %s\n", name->valuestring);
							}
						}
						else {
							switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "ASR event params error\n");
						}
					}
					else {
						if (status_message  && status_message->valuestring) {
							switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "ASR error: %s\n", status_message->valuestring);
						}
					}
				}

				cJSON_Delete(jason);
			}
		}
		else {
			
		}
		switch_micro_sleep(20 * 1000);
		//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "switch_micro_sleep\n");

	done:
		if (switch_test_flag(ali, PSFLAG_SPEECH_TIMEOUT)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "PSFLAG_SPEECH_TIMEOUT\n");
			if (switch_buffer_inuse(ali->text_result) > 0) {
				switch_set_flag_locked(ali, PSFLAG_HAS_TEXT);
				ali->confidence = 1;
			} else {
				switch_set_flag_locked(ali, PSFLAG_NOINPUT);
			}

			// Clear the queue
			while (switch_queue_trypop(ali->recognition_queue, &audio_buffer) == SWITCH_STATUS_SUCCESS) {
				if (audio_buffer) {
					switch_buffer_destroy(&audio_buffer);
				}
			}
		}
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Recognition thread stopped.\n");

	return ;
}

static void ali_nls_close_socket(ali_nls_t *nls)
{
	closesocket(nls->wsh.sock);
	nls->wsh.sock = ws_sock_invalid;
}

static switch_bool_t ali_nls_setup_socket(ali_nls_t *nls)
{
	struct addrinfo *ai;
	char buffer[URL_SIZE] = { 0 };
	const char *netip = NULL;
	const char *presip = NULL;
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	int ret = 0;

	for (ai = globals.api_ips; ai; ai = ai->ai_next) {
		if (ai->ai_family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
			memset(&addr, 0, sizeof(addr));
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = sin->sin_addr.s_addr;//inet_addr(ips->local_ip);
			addr.sin_port = htons(globals.api_port);
			netip = &addr.sin_addr;
		}
		else if (ai->ai_family == AF_INET6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ai->ai_addr;
			memset(&addr6, 0, sizeof(addr6));
			addr6.sin6_family = AF_INET6;
			addr6.sin6_addr = sin6->sin6_addr;
			addr6.sin6_port = htons(globals.api_port);
			//inet_pton(AF_INET6, ips->local_ip, &(addr6.sin6_addr));
			netip = &addr6.sin6_addr;
		}
		presip = switch_inet_ntop(ai->ai_family, netip, buffer, URL_SIZE);
		if (presip) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "IP4/6: %s.\n", presip);
		}

		//nls->wsh.sock = socket(ai->ai_family, SOCK_STREAM, IPPROTO_TCP);
		nls->wsh.sock = socket(ai->ai_family, SOCK_STREAM, 0);
		if (nls->wsh.sock < 0) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
				"Socket failed. aiFamily:%d, sockFd:%d. err msg\n", ai->ai_family, nls->wsh.sock);

			continue;
		}

		struct linger so_linger;
		so_linger.l_onoff = 1;
		so_linger.l_linger = 0;
		if (setsockopt(nls->wsh.sock, SOL_SOCKET, SO_LINGER, (char *)&so_linger, sizeof(struct linger)) > -1) {
			// 		if (evutil_make_socket_nonblocking(sockFd) < 0) {
			// 			LOG_ERROR("Node:%p evutil_make_socket_nonblocking failed.", this);
			// 			return -1;
			// 		}
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "New Socket ip:%s port:%d  fd:%d.\n",
				presip, globals.api_port, nls->wsh.sock);

			ret = 0;
			if (ai->ai_family == AF_INET) {
				ret = connect(nls->wsh.sock, (const struct sockaddr *)&addr, sizeof(struct sockaddr_in));
			}
			else {
				ret = connect(nls->wsh.sock, (const struct sockaddr *)&addr6, sizeof(struct sockaddr_in6));
			}

			if (ret == 0) {
				//ret = node->sslProcess();
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Begin gateway request process.\n");
				// 					if (nodeRequestProcess(node) == -1) {
				// 						destroyConnectNode(node);
				// 					}

				return SWITCH_TRUE;
				// 					LOG_INFO("Node:%p connected directly.", this);
				// 					setConnectNodeStatus(NodeConnected);}
			}
			else {
				// 					int error = error_code();
				// 					if (NLS_ERR_CONNECT_RETRIABLE(error)) {
				// 						/* _connectErrCode == 115(EINPROGRESS)
				// 						*  means connection is in progress,
				// 						*  normally the socket connecting timeout is 75s.
				// 						*  after the socket fd is ready to read.
				// 						*/
				// 						event_add(&_connectEvent, &_connectTv);
				// 						LOG_DEBUG("Connect would block:%d.", error);
				// 						return 1;
				// 					}
				// 					else {
				// 						LOG_ERROR("Node:%p Connect failed:%s. retry...",
				// 							this, evutil_socket_error_to_string(evutil_socket_geterror(_socketFd)));
				// 						return -1;
				// 					}
			}
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Set SO_LINGER failed.\n");
		}

		ali_nls_close_socket(nls);
	}

	return SWITCH_FALSE;
}

static switch_bool_t parse_token(const char *tokenstr)
{
	switch_bool_t ret = SWITCH_FALSE;
	cJSON *jason = NULL;
	switch_time_exp_t tm;
	char timestamp[80] = { 0 };
	switch_size_t retsize = 0;

	if (tokenstr && (jason = cJSON_Parse(tokenstr))) {
		cJSON *code = cJSON_GetObjectItem(jason, "Code");
		cJSON *token = cJSON_GetObjectItem(jason, "Token");

		if (token) {
			cJSON *id = cJSON_GetObjectItem(token, "Id");
			cJSON *expireTime = cJSON_GetObjectItem(token, "ExpireTime");
			switch_assert(id);
			switch_assert(expireTime);

			if (id) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Token: %s\n", id->valuestring);
				switch_snprintf(globals.token_id, sizeof(globals.token_id), "%s", id->valuestring);
			}
			if (expireTime) {
				globals.token_expire_time = expireTime->valueint;
				if (!switch_time_exp_lt(&tm, ((switch_time_t)(expireTime->valueint)) * 1000000) && !switch_strftime_nocheck(timestamp, &retsize, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm)) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ExpireTime: %s\n", timestamp);
				}
				else {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ExpireTime: %d\n", id->valueint);
				}
			}

			ret = SWITCH_TRUE;
		}
		else if (code && code->valuestring) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error code: %s\n", code->valuestring);
		}
		else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error result: %s\n", tokenstr);
		}

		cJSON_Delete(jason);
	}

	return ret;
}

static switch_bool_t save_token(const char *token, switch_memory_pool_t *pool)
{
	switch_size_t token_len;
	switch_file_t *fd;

	if (switch_file_open(&fd, globals.token_cache_pathfile,
		SWITCH_FOPEN_WRITE | SWITCH_FOPEN_CREATE | SWITCH_FOPEN_TRUNCATE,
		SWITCH_FPROT_UREAD | SWITCH_FPROT_UWRITE, pool) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Cannot open token cache file %s.\n", globals.token_cache_pathfile);
		return SWITCH_FALSE;
	}

	token_len = strlen(token);
	switch_file_write(fd, token, &token_len);
	switch_file_close(fd);

	return SWITCH_TRUE;
}

static switch_bool_t validate_token()
{
	if (globals.token_expire_time - switch_time_now() / 1000000 > 3600)
		return SWITCH_TRUE;
	else
		return SWITCH_FALSE;
}

static const char* ali_nls_get_token(switch_memory_pool_t *pool)
{
	CURL *curl_handle = NULL;
	switch_curl_slist_t *headers = NULL;
	char* body[512] = { 0 };
	switch_buffer_t *response = NULL;
	char req_params[512] = { 0 };
	char params_sign[512] = { 0 };
	char *url_path = NULL;
	switch_uuid_t uuid;
	char uuid_str[SWITCH_UUID_FORMATTED_LENGTH + 1];
	switch_time_exp_t tm;
	char timestamp[64] = { 0 };
	switch_size_t retsize = 0;
	char *token_id = NULL;
	char buf[512] = { 0 };

	if (validate_token())
		return globals.token_id;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Ali NLS begin get token.\n");
	switch_uuid_get(&uuid);
	switch_uuid_format(uuid_str, &uuid);

	if (switch_time_exp_gmt(&tm, switch_micro_time_now()) || switch_strftime_nocheck(buf, &retsize, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "get timestamp failure\n");
		goto done;
	}
	switch_url_encode_opt(buf, timestamp, sizeof timestamp, SWITCH_TRUE);


	switch_snprintf(req_params, sizeof req_params, "AccessKeyId=%s&Action=CreateToken&Format=JSON&RegionId=cn-shanghai"
		"&SignatureMethod=HMAC-SHA1&SignatureNonce=%s&SignatureVersion=1.0"
		"&Timestamp=%s&Version=2019-02-28", globals.access_key_id, uuid_str, timestamp);
	switch_url_encode_opt(req_params, params_sign, sizeof params_sign, SWITCH_TRUE);

	switch_url_encode_opt(globals.token_path, buf, sizeof buf, SWITCH_TRUE);
	url_path = switch_string_replace(buf, "/", "%2F");
	if (!url_path) {
		goto done;
	}
	switch_snprintf(buf, sizeof buf, "POST&%s&%s", url_path, params_sign);

	{
		unsigned char md[EVP_MAX_BLOCK_LENGTH] = { 0 };
		unsigned int mdLen = EVP_MAX_BLOCK_LENGTH;

		if (HMAC(EVP_sha1(), globals.access_key_secret, strlen(globals.access_key_secret), buf, strlen(buf), md, &mdLen) == NULL) {
			goto done;
		}
		EVP_EncodeBlock(buf, md, mdLen);
	}
	switch_url_encode(buf, params_sign, sizeof params_sign);
	switch_snprintf(body, sizeof body, "Signature=%s&%s", params_sign, req_params);

	switch_buffer_create_dynamic(&response, 1024 * 4, 1024 * 4, 0);
	switch_assert(response);

	curl_handle = switch_curl_easy_init();
	if (!curl_handle) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "switch_curl_easy_init() failure\n");
		goto done;
	}

	// 	sprintf(cur_time, "%lld", switch_time_now() / 1000000);
	// 	sprintf(buf, "%s%s%s", globals.access_key_secret, cur_time, param_b64);
	// 	switch_md5_string(check_sum, (void *)buf, strlen(buf));

	sprintf(buf, "Accept: application/json");
	headers = switch_curl_slist_append(headers, buf);
	sprintf(buf, "Content-type: application/x-www-form-urlencoded");
	headers = switch_curl_slist_append(headers, buf);

	switch_curl_easy_setopt(curl_handle, CURLOPT_POST, 1);
	switch_curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1);
	switch_curl_easy_setopt(curl_handle, CURLOPT_HEADER, 0);
	switch_curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
	switch_curl_easy_setopt(curl_handle, CURLOPT_URL, globals.token_url);

	//switch_curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, postParams.c_str()); // params  
	switch_curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
	switch_curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
	switch_curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 0);

	//switch_buffer_peek_zerocopy(audio_buffer, &body);
	//assert(body);
	switch_curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, body);

	//switch_curl_easy_setopt(curl_handle, CURLOPT_READFUNCTION, read_callback);
	//switch_curl_easy_setopt(curl_handle, CURLOPT_READDATA, (void *)asr_buffer);
	//switch_curl_easy_setopt(curl_handle, CURLOPT_HEADERFUNCTION, write_header_callback);
	//switch_curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, (void *)ifly);
	switch_curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_callback);
	switch_curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)response);

	switch_curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 10);
	switch_curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 10);

	switch_buffer_zero(response);

	switch_CURLcode httpRes = switch_curl_easy_perform(curl_handle);
	//switch_curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, httpRes);

	if (httpRes == CURLE_OK) {
		char *result = NULL;
		cJSON *jason = NULL;
		switch_buffer_write(response, "\0", 1);
		switch_buffer_peek_zerocopy(response, &result);
		if (result && parse_token(result)) {
			save_token(result, pool);
			token_id = globals.token_id;
		}
	}
	else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Received HTTP error %ld \n", httpRes);
	}

	if (curl_handle)
		switch_curl_easy_cleanup(curl_handle);

	if (headers) {
		switch_curl_slist_free_all(headers);
	}

done:

	if (response)
		switch_buffer_destroy(&response);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Ali NLS end get token.\n");

	return token_id;
}

/*! function to open the ASR interface */
static switch_status_t ali_asr_open(switch_asr_handle_t *ah, const char *codec, int rate, const char *dest, switch_asr_flag_t *flags)
{
	ali_nls_t *ali;
	int ret = 0;
	char* params = NULL;

	if (!(ali = (ali_nls_t *) switch_core_alloc(ah->memory_pool, sizeof(*ali)))) {
		return SWITCH_STATUS_MEMERR;
	}

	switch_mutex_init(&ali->flag_mutex, SWITCH_MUTEX_NESTED, ah->memory_pool);
	ah->private_info = ali;

	if (rate != 8000 && rate != 16000) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid rate %d. Only 8000 and 16000 are supported.\n", rate);
		return SWITCH_STATUS_FALSE;
	}

	codec = "L16";

	ah->codec = switch_core_strdup(ah->memory_pool, codec);

	switch_queue_create(&ali->recognition_queue, 100, ah->memory_pool);

	// Connect to Ali NLS
	if (!ali_nls_setup_socket(ali)) {
		return SWITCH_STATUS_FALSE;
	}
	ali->wsh.ssl_ctx = globals.ssl_ctx;
	ali->wsh.api_host = globals.api_host;
	ali->wsh.api_path = globals.api_path;
	ali->wsh.api_port = globals.api_port;
	ali->wsh.api_token = ali_nls_get_token(ah->memory_pool);
	ws_init(&ali->wsh);
	alinls_gen_uuid(ali->task_id, sizeof(ali->task_id));

	{
		cJSON *root, *header, *payload;
		char message_id[HEADER_UUID_LENGTH + 1] = "";
		root = cJSON_CreateObject();
		header = cJSON_CreateObject();
		payload = cJSON_CreateObject();
		if (header) {
			alinls_gen_uuid(message_id, sizeof message_id);
			cJSON_AddStringToObject(header, D_NAMESPACE, "SpeechTranscriber");
			cJSON_AddStringToObject(header, D_APP_KEY, globals.app_key);
			cJSON_AddStringToObject(header, D_TASK_ID, ali->task_id);
			cJSON_AddStringToObject(header, D_NAME, "StartTranscription");
			cJSON_AddStringToObject(header, D_MESSAGE_ID, message_id);
		}
		if (payload) {
			cJSON_AddStringToObject(payload, D_FORMAT, "PCM");
			cJSON_AddNumberToObject(payload, D_SAMPLE_RATE, rate);
			cJSON_AddTrueToObject(payload, D_SR_INTERMEDIATE_RESULT);
			cJSON_AddTrueToObject(payload, D_SR_PUNCTUATION_PREDICTION);
			cJSON_AddNumberToObject(payload, D_SR_MAX_SENTENCE_SILENCE, 500);
			cJSON_AddTrueToObject(payload, D_SR_DISFLUENCY);
			//cJSON_AddStringToObject(payload, D_SR_VOCABULARY_ID, "519172a510d6435bbca767c62414fe3e");
			//cJSON_AddTrueToObject(payload, D_SR_SENTENCE_DETECTION);
		}
		if (root) {
			if (header)
				cJSON_AddItemToObject(root, "header", header);
			if (payload)
				cJSON_AddItemToObject(root, "payload", payload);
			char *json_str = cJSON_Print(root);
			//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s\n", json_str);
			if (ws_write_frame(&ali->wsh, WSOC_TEXT, json_str, strlen(json_str)) == strlen(json_str))
			{

			}
			cJSON_Delete(root);
			root = NULL;
		}
		else {
			if (header) {
				cJSON_Delete(header);
				header = NULL;
			}
			if (payload) {
				cJSON_Delete(payload);
				payload = NULL;
			}
		}
	}
	
	switch_threadattr_t *thd_attr = NULL;
	switch_threadattr_create(&thd_attr, ah->memory_pool);
	switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
	switch_thread_create(&ali->recognition_thread, thd_attr, recognition_thread, ah, ah->memory_pool);

	if (!ali->audio_buffer) {
		switch_buffer_create_dynamic(&ali->audio_buffer, ALIYUN_BLOCK_SIZE, ALIYUN_BLOCK_SIZE, 0);
		switch_assert(ali->audio_buffer);
	}

	if (!ali->text_result) {
		switch_buffer_create_dynamic(&ali->text_result, 1024, 1024, 0);
		switch_assert(ali->text_result);
	}

	ali->listening = 0;
	ali->thresh = globals.thresh;
//	ali->silence_hits = globals.silence_hits;
	ali->listen_hits = globals.listen_hits;
//	ali->org_silence_hits = ali->silence_hits;
	ali->start_input_timers = globals.start_input_timers;
	ali->no_input_timeout = globals.no_input_timeout;
	ali->speech_timeout = globals.speech_timeout;
	ali->speech_pausetime = globals.speech_pausetime;
	ali->confidence_threshold = globals.confidence_threshold;
	ali->recognition_cliptime = globals.recognition_cliptime;

	return SWITCH_STATUS_SUCCESS;
}

/*! function to load a grammar to the ASR interface */
static switch_status_t ali_asr_load_grammar(switch_asr_handle_t *ah, const char *grammar, const char *name)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ali_asr_load_grammar: %s\n", grammar);
	char *gram_pathfile;
	char catlog[100] = {0};
	switch_file_t *gram_file_handle = NULL;
	ali_nls_t *ali = (ali_nls_t *) ah->private_info;
	
	ali->grammar.location = NULL;
	char *colon = strrchr(grammar, ':');
	if (colon){
		ali->grammar.file = switch_core_strndup(ah->memory_pool, grammar, colon - grammar);
		if (strlen(colon) > 1) { ali->grammar.location = strdup(colon + 1); }
	} else {
		ali->grammar.file = switch_core_strdup(ah->memory_pool, grammar);
	}

	if (switch_is_file_path(ali->grammar.file)) {
		char *dot = strrchr(grammar, '.');
		if (dot && !strcmp(dot, ".gram")) {
			gram_pathfile = strdup(grammar);
		} else {
			gram_pathfile = switch_mprintf("%s.gram", grammar);
		}
	} else {
		gram_pathfile = switch_mprintf("%s%s%s.gram", SWITCH_GLOBAL_dirs.grammar_dir, SWITCH_PATH_SEPARATOR, ali->grammar.file);
	}

	if (switch_file_open(&gram_file_handle, gram_pathfile, SWITCH_FOPEN_READ, SWITCH_FPROT_OS_DEFAULT, ah->memory_pool) == SWITCH_STATUS_SUCCESS){
		switch_size_t len = switch_file_get_size(gram_file_handle);
		if (len > 0) {
			ali->grammar.content = switch_core_alloc(ah->memory_pool, len + 1);
			if (ali->grammar.content) {
				if (switch_file_read(gram_file_handle, (void *)ali->grammar.content, &len) == SWITCH_STATUS_SUCCESS) {
					ali->grammar.root = cJSON_Parse(ali->grammar.content);
					if (ali->grammar.root) {
						char *name = strrchr(ali->grammar.location, '/');
						if (name) {
							strncpy(catlog, ali->grammar.location, name - ali->grammar.location);
							name++;
							ali->grammar.name = cJSON_GetObjectItem(
								cJSON_GetObjectItem(cJSON_GetObjectItem(ali->grammar.root, "grammar"), catlog), name);
						} else {
							switch_assert(0);
						}
					}
				}
			}
		}
	}
	if (gram_file_handle) switch_file_close(gram_file_handle);

	// Initialize variables
	ali->listening = 0;
	ali->pause_silence_time = 0;
	ali->timeout_silence_time = 0;
	if(ali->audio_buffer)
		switch_buffer_zero(ali->audio_buffer);
	if (ali->text_result)
		switch_buffer_zero(ali->text_result);
	
	switch_mutex_lock(ali->flag_mutex);
	switch_clear_flag(ali, PSFLAG_SPEECH_TIMEOUT);
	switch_clear_flag(ali, PSFLAG_NOINPUT_TIMEOUT);
	switch_clear_flag(ali, PSFLAG_INPUT_TIMERS);
	switch_set_flag(ali, PSFLAG_READY);
	switch_mutex_unlock(ali->flag_mutex);

	switch_safe_free(gram_pathfile);
	
	return SWITCH_STATUS_SUCCESS;
}

/*! function to unload a grammar to the ASR interface */
static switch_status_t ali_asr_unload_grammar(switch_asr_handle_t *ah, const char *name)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ali_asr_unload_grammar\n");
	return SWITCH_STATUS_SUCCESS;
}

/*! function to close the ASR interface */
static switch_status_t ali_asr_close(switch_asr_handle_t *ah, switch_asr_flag_t *flags)
{
	ali_nls_t *ali = (ali_nls_t *) ah->private_info;

	switch_set_flag_locked(ali, PSFLAG_ASRSTOP);
	if (ali->recognition_thread) {
		switch_status_t st;
		switch_thread_join(&st, ali->recognition_thread);
	}
	ws_destroy(&ali->wsh);

	switch_mutex_lock(ali->flag_mutex);
// 	if (switch_test_flag(ps, PSFLAG_ALLOCATED)) {
// 		if (switch_test_flag(ps, PSFLAG_READY)) { ps_end_utt(ps->ps); }
// 		ps_free(ps->ps);
// 		ps->ps = NULL;
// 	}
	if (ali->grammar.root) { 
		cJSON_Delete(ali->grammar.root);
		ali->grammar.root = NULL;
		ali->grammar.result = NULL;
	}

	switch_mutex_unlock(ali->flag_mutex);
	switch_clear_flag(ali, PSFLAG_HAS_TEXT);
// 	switch_clear_flag(ali, PSFLAG_NOINPUT);
// 	switch_clear_flag(ali, PSFLAG_NOMATCH);
	switch_clear_flag(ali, PSFLAG_READY);
	if (ali->text_result) {
		switch_buffer_destroy(&ali->text_result);
	}
	if (ali->audio_buffer) {
		switch_buffer_destroy(&ali->audio_buffer);
	}
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Port Closed.\n");
	switch_set_flag(ah, SWITCH_ASR_FLAG_CLOSED);
	return SWITCH_STATUS_SUCCESS;
}

static switch_bool_t silence_frame(ali_nls_t *ali, int16_t *data, unsigned int samples)
{
	uint32_t score, count = 0;
	double energy = 0;

	/* Do simple energy threshold for VAD */
	for (count = 0; count < samples; count++) {
		energy += abs(data[count]);
	}

	score = (uint32_t)(energy / samples);

	if (score >= ali->thresh) {
		return SWITCH_FALSE;
	}
	
	return SWITCH_TRUE;
}

static void do_recognition(ali_nls_t *ali)
{
	switch_buffer_t *recognition_buffer = NULL;
	
	switch_buffer_create_dynamic(&recognition_buffer, ALIYUN_BLOCK_SIZE, ALIYUN_BLOCK_SIZE, 0);
	switch_assert(recognition_buffer);

	if (recognition_buffer) {
		const switch_size_t step_size = 30;
		char buf_64[41], buf_ue[121];
		switch_size_t total = 0;
		char *src = NULL;

		switch_buffer_zero(recognition_buffer);
		switch_buffer_write(recognition_buffer, "audio=", 6);
		total = switch_buffer_peek_zerocopy(ali->audio_buffer, &src);
		for (switch_size_t i = 0; i + step_size <= total; i += step_size)
		{
			switch_b64_encode((unsigned char*)(src + i), step_size, (unsigned char*)buf_64, sizeof(buf_64));
			//buf_64[sizeof(buf_64) - 1] = '\0';
			switch_url_encode(buf_64, buf_ue, sizeof(buf_ue));
			switch_buffer_write(recognition_buffer, buf_ue, strlen(buf_ue));
		}
		switch_buffer_write(recognition_buffer, "\0", 1);

		if (switch_queue_push(ali->recognition_queue, recognition_buffer) != SWITCH_STATUS_SUCCESS) {
			switch_buffer_destroy(&recognition_buffer);
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "switch_queue_push fail\n");
		}
	}
	switch_buffer_zero(ali->audio_buffer);
}

/*! function to feed audio to the ASR */
static switch_status_t ali_asr_feed(switch_asr_handle_t *ah, void *data, unsigned int len, switch_asr_flag_t *flags)
{
	ali_nls_t *ali = (ali_nls_t *) ah->private_info;

	if (switch_test_flag(ah, SWITCH_ASR_FLAG_CLOSED))
		return SWITCH_STATUS_BREAK;

	if (!switch_test_flag(ali, PSFLAG_NOMATCH) && !switch_test_flag(ali, PSFLAG_NOINPUT) && !switch_test_flag(ali, PSFLAG_HAS_TEXT) 
		&& !switch_test_flag(ali, PSFLAG_SPEECH_TIMEOUT) && switch_test_flag(ali, PSFLAG_READY)) {
		switch_time_t now_ms = switch_micro_time_now() / 1000;
		if (!silence_frame(ali, (int16_t *)data, len / 2)) {
			if (++ali->listening == ali->listen_hits) {
				switch_set_flag_locked(ali, PSFLAG_START_OF_SPEECH);
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "ASR speech start\n");
			}
			if (ali->pause_silence_time) {
				ali->pause_silence_time = 0;
				//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "ASR speech(pause)\n");
			}
			if (switch_test_flag(ali, PSFLAG_INPUT_TIMERS) && ali->timeout_silence_time) {
				ali->timeout_silence_time = 0;
				//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "ASR speech(timeout)\n");
			}
		} else {
			if (!ali->pause_silence_time) {
				ali->pause_silence_time = now_ms;
				//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "ASR silence(pause)\n");
			}
			if (switch_test_flag(ali, PSFLAG_INPUT_TIMERS) && !ali->timeout_silence_time) {
				ali->timeout_silence_time = now_ms;
				//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "ASR silence(timeout)\n");
			}
		}

		/* Check speech pause */
// 		if (ali->pause_silence_time && (now_ms - ali->pause_silence_time) >= ali->speech_pausetime) {
// 			switch_size_t samples = switch_buffer_inuse(ali->audio_buffer) / 2;
// 			if (samples * 1000 / ah->native_rate >= (switch_size_t)ali->recognition_cliptime) {
// 				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "ASR speech pause\n");
// 				do_recognition(ali);
// 			}
// 		}

		/* Check speech timeout */
		if (switch_test_flag(ali, PSFLAG_INPUT_TIMERS) && ali->timeout_silence_time) {
			switch_time_t elapsed_ms = now_ms - ali->timeout_silence_time;
			if (switch_test_flag(ali, PSFLAG_START_OF_SPEECH)) {
				if (!switch_test_flag(ali, PSFLAG_SPEECH_TIMEOUT) && elapsed_ms >= ali->speech_timeout) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "ASR speech timeout\n");
					switch_set_flag_locked(ali, PSFLAG_SPEECH_TIMEOUT);
					ali->listening = 0;
					//do_recognition(ali);
				}
			} else {
				if (!switch_test_flag(ali, PSFLAG_NOINPUT_TIMEOUT) && elapsed_ms >= ali->no_input_timeout) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "ASR speech noinput timeout\n");
					switch_mutex_lock(ali->flag_mutex);
					switch_set_flag(ali, PSFLAG_NOINPUT_TIMEOUT);
					switch_set_flag(ali, PSFLAG_NOINPUT);
					switch_mutex_unlock(ali->flag_mutex);
					ali->listening = 0;
				}
			}
		}

		/* only save data ali nls is listening */
		if (ali->listening && data && len > 0) {
			switch_buffer_write(ali->audio_buffer, data, len);
			switch_size_t used = switch_buffer_inuse(ali->audio_buffer);
			if (used + len > ALIYUN_BLOCK_SIZE) {
// 				uint8_t audio_data[ALIYUN_BLOCK_SIZE];
// 				switch_size_t len = switch_buffer_read(ali->audio_buffer, audio_data, ALIYUN_BLOCK_SIZE);
// 				switch_size_t ret = ws_write_frame(&ali->wsh, WSOC_BINARY, audio_data, len);
// 				if (ret != len) {
// 					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Send audio fail\n");
// 				}
// 				else {
// 					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Send audio %d bytes\n", ret);
// 				}
//				switch_buffer_zero(ali->audio_buffer);
				if (switch_queue_push(ali->recognition_queue, ali->audio_buffer) != SWITCH_STATUS_SUCCESS) {
					switch_buffer_zero(ali->audio_buffer);
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "switch_queue_push fail\n");
				}
				else {
					switch_buffer_create_dynamic(&ali->audio_buffer, ALIYUN_BLOCK_SIZE, ALIYUN_BLOCK_SIZE, 0);
					switch_assert(ali->audio_buffer);
					//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Queue audio data\n");
				}
			}
		}
	}

	return SWITCH_STATUS_SUCCESS;
}

/*! function to pause recognizer */
static switch_status_t ali_asr_pause(switch_asr_handle_t *ah)
{
	ali_nls_t *ali = (ali_nls_t *)ah->private_info;

	switch_set_flag_locked(ali, PSFLAG_ASRSTOP);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ali_asr_pause\n");
	return SWITCH_STATUS_SUCCESS;
}

/*! function to resume recognizer */
static switch_status_t ali_asr_resume(switch_asr_handle_t *ah)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ali_asr_resume\n");
	return SWITCH_STATUS_SUCCESS;
}

/*! function to read results from the ASR*/
static switch_status_t ali_asr_check_results(switch_asr_handle_t *ah, switch_asr_flag_t *flags)
{
	ali_nls_t *ali = (ali_nls_t *) ah->private_info;

	return (switch_test_flag(ali, PSFLAG_NOINPUT) || switch_test_flag(ali, PSFLAG_NOMATCH) || switch_test_flag(ali, PSFLAG_HAS_TEXT))
		? SWITCH_STATUS_SUCCESS : SWITCH_STATUS_FALSE;
}

/*! function to read results from the ASR */
static switch_status_t ali_asr_get_results(switch_asr_handle_t *ah, char **xmlstr, switch_asr_flag_t *flags)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "ali_asr_get_results\n");
	ali_nls_t *ali = (ali_nls_t *) ah->private_info;
	//switch_status_t status = SWITCH_STATUS_SUCCESS;

	//if (switch_test_flag(ps, PSFLAG_BARGE)) {
	//	switch_clear_flag_locked(ps, PSFLAG_BARGE);
	//	status = SWITCH_STATUS_BREAK;
	//}
	if (switch_test_flag(ali, PSFLAG_HAS_TEXT)) {
		switch_clear_flag_locked(ali, PSFLAG_HAS_TEXT);

		//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Recognized: %s, Confidence: %d, Confidence-Threshold: %d\n", ps->hyp, ps->confidence, ps->confidence_threshold);
		
		const char* result = NULL;
		switch_buffer_write(ali->text_result, "\0", 1);
		switch_buffer_peek_zerocopy(ali->text_result, &result);

		if (result && strlen(result) > 0) {
			*xmlstr = switch_mprintf("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
									 "<result grammar=\"%s\">\n"
									 "  <interpretation grammar=\"%s\" confidence=\"%d\">\n"
									 "    <input mode=\"speech\">%s</input>\n"
									 "  </interpretation>\n"
									 "</result>\n",
									 ali->grammar.location, ali->grammar.location,
									 ali->grammar.result ? ali->grammar.confidence : ali->confidence,
									 ali->grammar.result ? ali->grammar.result->valuestring : result);

			//if (!switch_test_flag(ps, PSFLAG_INPUT_TIMERS) && switch_test_flag(ah, SWITCH_ASR_FLAG_AUTO_RESUME)) {
			//	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Auto Resuming\n");
			//	switch_set_flag(ps, PSFLAG_READY);
			//}
			return SWITCH_STATUS_SUCCESS;
		} else {
			switch_set_flag_locked(ali, PSFLAG_NOINPUT);
		}
	}
	
	if (switch_test_flag(ali, PSFLAG_NOMATCH)) {
		switch_clear_flag_locked(ali, PSFLAG_NOMATCH);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "NO MATCH\n");

		*xmlstr = switch_mprintf(
			"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
			"<result grammar=\"%s\">\n"
			"  <interpretation>\n"
			"    <input mode=\"speech\"><nomatch/></input>\n"
			"  </interpretation>\n"
			"</result>\n",
			ali->grammar);

		return SWITCH_STATUS_SUCCESS;
	}
	
	if (switch_test_flag(ali, PSFLAG_NOINPUT)) {
		switch_clear_flag_locked(ali, PSFLAG_NOINPUT);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "NO INPUT\n");

		*xmlstr = switch_mprintf(
			"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
			"<result grammar=\"%s\">\n"
			"  <interpretation>\n"
			"    <input mode=\"speech\"><noinput/></input>\n"
			"  </interpretation>\n"
			"</result>\n",
			ali->grammar);

		return SWITCH_STATUS_SUCCESS;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "ali_asr_get_results error!!!\n");
	return SWITCH_STATUS_FALSE;
}

/*! function to start input timeouts */
static switch_status_t ali_asr_start_input_timers(switch_asr_handle_t *ah)
{
	ali_nls_t *ali = (ali_nls_t *) ah->private_info;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ali_asr_start_input_timers\n");
	switch_set_flag_locked(ali, PSFLAG_INPUT_TIMERS);
	return SWITCH_STATUS_SUCCESS;
}

/*! set text parameter */
static void ali_asr_text_param(switch_asr_handle_t *ah, char *param, const char *val)
{
	ali_nls_t *ali = (ali_nls_t *) ah->private_info;
	if (!zstr(param) && !zstr(val)) {
		if (!strcasecmp("no-input-timeout", param) && switch_is_number(val)) {
			ali->no_input_timeout = atoi(val);
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "no-input-timeout = %d\n", ali->no_input_timeout);
		} else if (!strcasecmp("speech-timeout", param) && switch_is_number(val)) {
			ali->speech_timeout = atoi(val);
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "speech-timeout = %d\n", ali->speech_timeout);
		} else if (!strcasecmp("speech-pausetime", param) && switch_is_number(val)) {
			ali->speech_pausetime = atoi(val);
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "speech-pausetime = %d\n", ali->speech_pausetime);
		} else if (!strcasecmp("recognition-cliptime", param) && switch_is_number(val)) {
			ali->recognition_cliptime = atoi(val);
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "recognition-cliptime = %d\n", ali->recognition_cliptime);
		} else if (!strcasecmp("start-input-timers", param)) {
			ali->start_input_timers = switch_true(val);
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "start-input-timers = %d\n", ali->start_input_timers);
		} else if (!strcasecmp("confidence-threshold", param) && switch_is_number(val)) {
			ali->confidence_threshold = atoi(val);
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "confidence-threshold = %d\n", ali->confidence_threshold);
		}
	}
}

/*! set numeric parameter */
static void ali_asr_numeric_param(switch_asr_handle_t *ah, char *param, int val)
{
	char *val_str = switch_mprintf("%d", val);
	ali_asr_text_param(ah, param, val_str);
	switch_safe_free(val_str);
}

/*! set float parameter */
static void ali_asr_float_param(switch_asr_handle_t *ah, char *param, double val)
{
	char *val_str = switch_mprintf("%f", val);
	ali_asr_text_param(ah, param, val_str);
	switch_safe_free(val_str);
}

static switch_bool_t parse_url(const char *urlstr, url_t *url)
{
	if (!urlstr)
		return SWITCH_FALSE;

	if (sscanf(urlstr, "%[^:/]://%[^:/]:%d/%s", url->protocal, url->host, &url->port, url->path) == 4) {
		if (strcmp(url->protocal, "wss") == 0 || strcmp(url->protocal, "https") == 0) {
			url->secure = SWITCH_TRUE;
		}
	}
	else if (sscanf(urlstr, "%[^:/]://%[^:/]/%s", url->protocal, url->host, url->path) == 3) {
		if (strcmp(url->protocal, "wss") == 0 || strcmp(url->protocal, "https") == 0) {
			url->port = 443;
			url->secure = SWITCH_TRUE;
		}
	}
	else if (sscanf(urlstr, "%[^:/]://%[^:/]:%d", url->protocal, url->host, &url->port) == 3) {
		if (strcmp(url->protocal, "wss") == 0 || strcmp(url->protocal, "https") == 0) {
			url->secure = SWITCH_TRUE;
		}
		url->path[0] = '\0';
	}
	else if (sscanf(urlstr, "%[^:/]://%[^:/]", url->protocal, url->host) == 2) {
		if (strcmp(url->protocal, "wss") == 0 || strcmp(url->protocal, "https") == 0) {
			url->port = 443;
			url->secure = SWITCH_TRUE;
		}
		// 		else {
		// 			globals.api_port = 80;
		// 		}
		url->path[0] = '\0';
	}
	else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Could not parse url: %s\n", urlstr);
		return SWITCH_FALSE;
	}

	return SWITCH_TRUE;
}

static switch_status_t load_config(void)
{
	char *cf = "aliasr.conf";
	switch_xml_t cfg, xml = NULL, param, settings;
	switch_status_t status = SWITCH_STATUS_SUCCESS;
	url_t url;

	/* Set defaults */
	globals.thresh = 400;
//	globals.silence_hits = 35;
	globals.listen_hits = 2;
	globals.start_input_timers = SWITCH_FALSE;
	globals.no_input_timeout = 5000;
	globals.speech_timeout = 3000;
	globals.speech_pausetime = 1000;
	globals.confidence_threshold = 0;
	globals.recognition_cliptime = 5000;
	//globals.auto_reload = 1;

	if (!(xml = switch_xml_open_cfg(cf, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Open of %s failed\n", cf);
		status = SWITCH_STATUS_FALSE;
		goto done;
	}

	if ((settings = switch_xml_child(cfg, "settings"))) {
		for (param = switch_xml_child(settings, "param"); param; param = param->next) {
			char *var = (char *) switch_xml_attr_soft(param, "name");
			char *val = (char *) switch_xml_attr_soft(param, "value");
			if (!strcasecmp(var, "threshold")) {
				globals.thresh = atoi(val);
			} else if (!strcasecmp(var, "start-input-timers")) {
				globals.start_input_timers = switch_true(val);
			} else if (!strcasecmp(var, "no-input-timeout")) {
				globals.no_input_timeout = atoi(val);
			} else if (!strcasecmp(var, "speech-timeout")) {
				globals.speech_timeout = atoi(val);
			} else if (!strcasecmp(var, "speech-pausetime")) {
				globals.speech_pausetime = atoi(val);
			} else if (!strcasecmp(var, "recognition-cliptime")) {
				globals.recognition_cliptime = atoi(val);
			} else if (!strcasecmp(var, "confidence_threshold")) {
				globals.confidence_threshold = atoi(val);
			//} else if (!strcasecmp(var, "silence-hits")) {
			//	globals.silence_hits = atoi(val);
			//} else if (!strcasecmp(var, "language-weight")) {
			//	globals.language_weight = switch_core_strdup(globals.pool, val);
			} else if (!strcasecmp(var, "listen-hits")) {
				globals.listen_hits = atoi(val);
			//} else if (!strcasecmp(var, "auto-reload")) {
			//	globals.auto_reload = switch_true(val);
			} else if (!strcasecmp(var, "api-url")) {
				globals.api_url = switch_core_strdup(globals.pool, val);
			} else if (!strcasecmp(var, "token-url")) {
				globals.token_url = switch_core_strdup(globals.pool, val);
			} else if (!strcasecmp(var, "app-key")) {
				globals.app_key = switch_core_strdup(globals.pool, val);
			} else if (!strcasecmp(var, "access-key-id")) {
				globals.access_key_id = switch_core_strdup(globals.pool, val);
			} else if (!strcasecmp(var, "access-key-secret")) {
				globals.access_key_secret = switch_core_sprintf(globals.pool, "%s&", val);
			//} else if (!strcasecmp(var, "dictionary")) {
			//	globals.dictionary = switch_core_strdup(globals.pool, val);
			}
		}
	}

// 	if (!globals.api_url) {
// 		globals.api_url = switch_core_strdup(globals.pool, "wss://nls-gateway.cn-shanghai.aliyuncs.com/ws/v1");
// 	}
	
	if (!globals.api_url || !globals.token_url || !globals.app_key || !globals.access_key_id || !globals.access_key_secret) {
		status = SWITCH_STATUS_FALSE;
	}

	globals.token_cache_pathfile = switch_core_sprintf(globals.pool, "%s%sali_nls_token.dat", SWITCH_GLOBAL_dirs.run_dir, SWITCH_PATH_SEPARATOR);
	if (!globals.token_cache_pathfile || switch_dir_make_recursive(SWITCH_GLOBAL_dirs.run_dir, SWITCH_DEFAULT_DIR_PERMS, globals.pool)) {
		status = SWITCH_STATUS_FALSE;
	}

	// Parse token url
	memset(&url, 0, sizeof(url_t));
	url.port = 80;
	url.secure = SWITCH_FALSE;
	if (parse_url(globals.token_url, &url)) {
		switch_snprintf(url.host, sizeof url.host, "/%s", url.path);
		switch_url_encode_opt(url.host, url.path, sizeof url.path, SWITCH_FALSE);
		globals.token_path = switch_core_sprintf(globals.pool, "%s", url.path);
		//if (!switch_strcasecmp_any("/", globals.token_path)) {
		//	// To do: allow any token url path
		//	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Token url path must be '/'\n");
		//	status = SWITCH_STATUS_FALSE;
		//	goto done;
		//}
	}
	else {
		status = SWITCH_STATUS_FALSE;
		goto done;
	}

	// Parse API url
	memset(&url, 0, sizeof(url_t));
	url.port = 80;
	url.secure = SWITCH_FALSE;
	if (parse_url(globals.api_url, &url)) {
		globals.api_port = url.port;
		globals.api_secure = url.secure;
		globals.api_host = switch_core_sprintf(globals.pool, "%s", url.host);
		globals.api_path = switch_core_sprintf(globals.pool, "/%s", url.path);
		if (globals.api_ips) {
			freeaddrinfo(globals.api_ips);
			globals.api_ips = NULL;
		}
		if (getaddrinfo(url.host, 0, 0, &globals.api_ips)) {
			status = SWITCH_STATUS_FALSE;
			goto done;
		}
		//get_addr(buf, buflen, ai->ai_addr, sizeof(struct sockaddr_storage));
	}
	else {
		status = SWITCH_STATUS_FALSE;
		goto done;
	}

	if (globals.thresh < 100)
		globals.thresh = 100;
	if (globals.thresh > 1000)
		globals.thresh = 1000;

	if (globals.listen_hits < 1)
		globals.listen_hits = 1;
	if (globals.listen_hits > 10)
		globals.listen_hits = 10;

	if (globals.no_input_timeout < 2000)
		globals.no_input_timeout = 2000;
	if (globals.no_input_timeout > 10000)
		globals.no_input_timeout = 10000;

	if (globals.speech_timeout < 2000)
		globals.speech_timeout = 2000;
	if (globals.speech_timeout > 10000)
		globals.speech_timeout = 10000;

	if (globals.recognition_cliptime < 2000)
		globals.recognition_cliptime = 2000;
	if (globals.recognition_cliptime > 50000)
		globals.recognition_cliptime = 50000;

	if (globals.speech_pausetime < 200)
		globals.speech_pausetime = 200;
	if (globals.speech_pausetime > 3000)
		globals.speech_pausetime = 3000;

	//if (!globals.dictionary) {
	//	globals.dictionary = switch_core_strdup(globals.pool, "default.dic");
	//}
	//
	//if (!globals.language_weight) {
	//	globals.language_weight = switch_core_strdup(globals.pool, "6.5");
	//}


// 		if (!strcmp(conference_log_dir, "auto")) {
// 			path = switch_core_sprintf(conference->pool, "%s%sconference_cdr", SWITCH_GLOBAL_dirs.log_dir, SWITCH_PATH_SEPARATOR);
// 		}
// 		else if (!switch_is_file_path(conference_log_dir)) {
// 			path = switch_core_sprintf(conference->pool, "%s%s%s", SWITCH_GLOBAL_dirs.log_dir, SWITCH_PATH_SEPARATOR, conference_log_dir);
// 		}
// 		else {
// 			path = switch_core_strdup(conference->pool, conference_log_dir);
// 		}
//		switch_dir_make_recursive(path, SWITCH_DEFAULT_DIR_PERMS, conference->pool);
//		conference->log_dir = path;


  done:
	if (xml) {
		switch_xml_free(xml);
	}

	return status;
}

static void load_token(void)
{
	char token_buffer[2048] = "";
	switch_size_t token_len;
	switch_file_t *fd;

	if (switch_file_open(&fd, globals.token_cache_pathfile,
		SWITCH_FOPEN_READ, SWITCH_FPROT_UREAD | SWITCH_FPROT_UWRITE, globals.pool) != SWITCH_STATUS_SUCCESS) {
		//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Cannot open token cache file %s.\n", globals.token_cache_pathfile);
		return ;
	}

	memset(token_buffer, 0, sizeof(token_buffer));
	token_len = sizeof(token_buffer) - 1;
	switch_file_read(fd, token_buffer, &token_len);
	switch_file_close(fd);
	if (token_len < 1) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Cannot read token from cache file %s.\n", globals.token_cache_pathfile);
		return ;
	}

	parse_token(token_buffer);
}

static ws_socket_t prepare_socket4(const char *ips)
{
	ws_socket_t sock = ws_sock_invalid;
#ifndef WIN32
	int reuse_addr = 1;
#else
	char reuse_addr = 1;
#endif
	int family;
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;

	if (strchr(ips, ':')) {
		family = PF_INET6;
	}
	else {
		family = PF_INET;
	}

	if ((sock = socket(family, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		die("Socket Error!\n");
	}

	//if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr)) < 0) {
	//	die("Socket setsockopt Error!\n");
	//}

	if (family == PF_INET) {
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = inet_addr(ips);
		addr.sin_port = htons(443);
		if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
			die("Bind Error!\n");
		}
	}
	else {
		memset(&addr6, 0, sizeof(addr6));
		addr6.sin6_family = AF_INET6;
		addr6.sin6_port = htons(443);
		inet_pton(AF_INET6, ips, &(addr6.sin6_addr));
		if (connect(sock, (struct sockaddr *) &addr6, sizeof(addr6)) < 0) {
			die("Bind Error!\n");
		}
	}

	//if (listen(sock, MAXPENDING) < 0) {
	//	die("Listen error\n");
	//}

	//ips->family = family;

	return sock;

error:

	close_file(&sock);

	return ws_sock_invalid;
}

// static ws_socket_t prepare_socket2(ali_nls_t *ali)
// {
// 	ws_socket_t sock = ws_sock_invalid;
// #ifndef WIN32
// 	int reuse_addr = 1;
// #else
// 	char reuse_addr = 1;
// #endif
// 	int family;
// 	struct sockaddr_in addr;
// 	struct sockaddr_in6 addr6;
// 
// 	if (strchr(ips->local_ip, ':')) {
// 		family = PF_INET6;
// 	}
// 	else {
// 		family = PF_INET;
// 	}
// 
// 	if ((sock = socket(family, SOCK_STREAM, IPPROTO_TCP)) < 0) {
// 		die("Socket Error!\n");
// 	}
// 
// 	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr)) < 0) {
// 		die("Socket setsockopt Error!\n");
// 	}
// 
// 	if (family == PF_INET) {
// 		memset(&addr, 0, sizeof(addr));
// 		addr.sin_family = AF_INET;
// 		addr.sin_addr.s_addr = inet_addr(ips->local_ip);
// 		addr.sin_port = htons(ips->local_port);
// 		if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
// 			die("Bind Error!\n");
// 		}
// 	}
// 	else {
// 		memset(&addr6, 0, sizeof(addr6));
// 		addr6.sin6_family = AF_INET6;
// 		addr6.sin6_port = htons(ips->local_port);
// 		inet_pton(AF_INET6, ips->local_ip, &(addr6.sin6_addr));
// 		if (bind(sock, (struct sockaddr *) &addr6, sizeof(addr6)) < 0) {
// 			die("Bind Error!\n");
// 		}
// 	}
// 
// 	if (listen(sock, MAXPENDING) < 0) {
// 		die("Listen error\n");
// 	}
// 
// 	ips->family = family;
// 
// 	return sock;
// 
// error:
// 
// 	close_file(&sock);
// 
// 	return ws_sock_invalid;
// }

static switch_status_t ali_nls_disconnect(ali_nls_t *nls) {
	/* send SSL/TLS close_notify */
	SSL_shutdown(nls->wsh.ssl);

	/* Clean up. */
	SSL_free(nls->wsh.ssl);
	SSL_CTX_free(nls->wsh.ssl_ctx);
	ali_nls_close_socket(nls);
}

static switch_status_t ali_nls_connect(ali_nls_t *nls) {
	int err;
	ws_socket_t sd = nls->wsh.sock;
	SSL_CTX* ctx = nls->wsh.ssl_ctx;
	SSL*     ssl = nls->wsh.ssl;
	X509*    server_cert;
	char*    str;
	char     buf[4096];
	SSL_METHOD *meth;

	SSL_library_init();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(SSLv23_client_method());//                        CHK_NULL(ctx);

	SSL_CTX_set_mode(ctx,
		SSL_MODE_ENABLE_PARTIAL_WRITE |
		SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
		SSL_MODE_AUTO_RETRY);

	/* Create a socket and connect to server using normal socket calls. */
	//sd = prepare_socket("106.15.83.70");

	/* Now we have TCP connection. Start SSL negotiation. */
	ssl = SSL_new(ctx);
	if (NULL == ssl)
		return SWITCH_STATUS_FALSE;
	if (!SSL_set_fd(ssl, sd)) {
		closesocket(sd);
		return SWITCH_STATUS_FALSE;
	}
	err = SSL_connect(ssl);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "SSL connection using %s\n",
		SSL_get_cipher(ssl));

	if (1) {
		/* Get server's certificate (note: beware of dynamic allocation) - opt */
		server_cert = SSL_get_peer_certificate(ssl);       //CHK_NULL(server_cert);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Server certificate:\n");

		str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
		//CHK_NULL(str);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "\t subject: %s\n", str);
		OPENSSL_free(str);

		str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
		//CHK_NULL(str);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "\t issuer: %s\n", str);
		OPENSSL_free(str);

		/* We could do all sorts of certificate verification stuff here before
		deallocating the certificate. */

		X509_free(server_cert);
	}

	return SWITCH_STATUS_SUCCESS;
}

static void do_load(void)
{
	switch_mutex_lock(MUTEX);
	load_config();
	load_token();
	switch_mutex_unlock(MUTEX);
}

static void event_handler(switch_event_t *event)
{
// 	if (globals.auto_reload) {
// 		do_load();
// 		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Ali ASR Reloaded\n");
// 	}
}

SWITCH_MODULE_LOAD_FUNCTION(mod_aliasr_load)
{
	switch_asr_interface_t *asr_interface;

	switch_mutex_init(&MUTEX, SWITCH_MUTEX_NESTED, pool);

	globals.pool = pool;

	do_load();

	if (ali_nls_get_token(pool) == NULL) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't get ali ns token!\n");
		return SWITCH_STATUS_TERM;
	}

// 	ali_nls_t *ali;
// 	switch_bool_t ret = 0;
// 	char* params = NULL;
// 
// 	if (!(ali = (ali_nls_t *)switch_core_alloc(pool, sizeof(*ali)))) {
// 		return SWITCH_STATUS_TERM;
// 	}
	init_ssl();


	if ((switch_event_bind_removable(modname, SWITCH_EVENT_RELOADXML, NULL, event_handler, NULL, &NODE) != SWITCH_STATUS_SUCCESS)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't bind!\n");
	}

	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	asr_interface = switch_loadable_module_create_interface(*module_interface, SWITCH_ASR_INTERFACE);
	asr_interface->interface_name = "aliasr";
	asr_interface->asr_open = ali_asr_open;
	asr_interface->asr_load_grammar = ali_asr_load_grammar;
	asr_interface->asr_unload_grammar = ali_asr_unload_grammar;
	asr_interface->asr_close = ali_asr_close;
	asr_interface->asr_feed = ali_asr_feed;
	asr_interface->asr_resume = ali_asr_resume;
	asr_interface->asr_pause = ali_asr_pause;
	asr_interface->asr_check_results = ali_asr_check_results;
	asr_interface->asr_get_results = ali_asr_get_results;
	asr_interface->asr_start_input_timers = ali_asr_start_input_timers;
	asr_interface->asr_text_param = ali_asr_text_param;
	asr_interface->asr_numeric_param = ali_asr_numeric_param;
	asr_interface->asr_float_param = ali_asr_float_param;

	/* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_aliasr_shutdown)
{
	if (globals.api_ips)
		freeaddrinfo(globals.api_ips);
	deinit_ssl();

	switch_event_unbind(&NODE);
	return SWITCH_STATUS_UNLOAD;
}


/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4 noet:
 */
