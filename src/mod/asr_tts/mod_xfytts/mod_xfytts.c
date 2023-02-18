/* 
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2014, Anthony Minessale II <anthm@freeswitch.org>
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
 * Raymond Chandler <intralanman@freeswitch.org>
 *
 * mod_xfytts.c -- xfyun TTS Interface
 *
 */

#include <switch.h>
#include <switch_curl.h>
#include <switch_utils.h>
#include <switch_apr.h>
#include "fspr_file_io.h"

SWITCH_MODULE_LOAD_FUNCTION(mod_xfytts_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_xfytts_shutdown);
SWITCH_MODULE_DEFINITION(mod_xfytts, mod_xfytts_load, mod_xfytts_shutdown, NULL);

static switch_mutex_t *MUTEX = NULL;
static switch_event_node_t *NODE = NULL;

static struct {
	//int no_input_timeout;
	switch_bool_t cache_audio;
	char* cache_dir;
	switch_time_t cache_expire;
	char* api_url;
	char* app_id;
	char* api_key;
	switch_memory_pool_t *pool;
} globals;

typedef struct {
	char *voice_name;
	switch_bool_t getting_header;
	switch_bool_t getting_body;
	switch_bool_t got_audio;
	int content_len;
	switch_buffer_t *audio_buffer;
}xfy_t;

typedef struct _wave_pcm_hdr
{
	char            riff[4];                // = "RIFF"
	int				size_8;                 // = FileSize - 8
	char            wave[4];                // = "WAVE"
	char            fmt[4];                 // = "fmt "
	int				fmt_size;				// = 下一个结构体的大小 : 16

	short int       format_tag;             // = PCM : 1
	short int       channels;               // = 通道数 : 1
	int				samples_per_sec;        // = 采样率 : 8000 | 6000 | 11025 | 16000
	int				avg_bytes_per_sec;      // = 每秒字节数 : samples_per_sec * bits_per_sample / 8
	short int       block_align;            // = 每采样点字节数 : wBitsPerSample / 8
	short int       bits_per_sample;        // = 量化比特数: 8 | 16

	char            data[4];                // = "data";
	int				data_size;              // = 纯数据长度 : FileSize - 44 
} wave_pcm_hdr;

#define XFY_BLOCK_SIZE 1024 * 32

switch_time_t file_get_mtime(switch_file_t *thefile)
{
	struct fspr_finfo_t finfo;
	return fspr_file_info_get(&finfo, APR_FINFO_SIZE, thefile) == SWITCH_STATUS_SUCCESS ? (switch_size_t)finfo.mtime : 0;
}

static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userp)
{
	xfy_t *xfy = (xfy_t *)userp;

	if (xfy->getting_header) {
		if (switch_string_match((const char*)ptr, size*nmemb, "\r\n", 2) == SWITCH_STATUS_SUCCESS) {
			// Headers done
			if (xfy->content_len > 0) {
				xfy->getting_header = SWITCH_FALSE;
				xfy->getting_body = SWITCH_TRUE;
			}
		} else if (switch_stristr("audio/mpeg", (const char*)ptr)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "xfytts got audio\n");
			xfy->got_audio = TRUE;
		} else if (switch_stristr("Content-Length", (const char*)ptr)) {
			const char* pos = switch_stristr(":", (const char*)ptr);
			if (pos) {
				pos++;
				xfy->content_len = atoi(pos);
			}
		}
	} else if (xfy->getting_body) {
		if (xfy->got_audio) {
			if (!xfy->audio_buffer) {
				switch_buffer_create_dynamic(&xfy->audio_buffer, XFY_BLOCK_SIZE, xfy->content_len, 0);
				switch_assert(xfy->audio_buffer);
			}

			if (xfy->audio_buffer) {
				switch_buffer_write(xfy->audio_buffer, ptr, size * nmemb);
			}
		}
	} else {
		assert(0);
	}

	return size*nmemb;
}

static switch_status_t xfy_speech_open(switch_speech_handle_t *sh, const char *voice_name, int rate, int channels, switch_speech_flag_t *flags)
{
	xfy_t *xfy = switch_core_alloc(sh->memory_pool, sizeof(*xfy));

	sh->native_rate = rate;

	if (!voice_name || !*voice_name) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "A voice is required. For example: xiaoyan.\n");
		return SWITCH_STATUS_FALSE;
	}

	xfy->voice_name = switch_core_strdup(sh->memory_pool, voice_name);

	if (xfy->voice_name) {
		sh->private_info = xfy;
		return SWITCH_STATUS_SUCCESS;
	}

	return SWITCH_STATUS_FALSE;
}

static switch_status_t xfy_speech_close(switch_speech_handle_t *sh, switch_speech_flag_t *flags)
{
	xfy_t *xfy = (xfy_t *) sh->private_info;

	if (xfy->audio_buffer) {
		switch_buffer_destroy(&xfy->audio_buffer);
	}

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t xfy_speech_feed_tts(switch_speech_handle_t *sh, char *text, switch_speech_flag_t *flags)
{
	xfy_t *xfy = (xfy_t *)sh->private_info;
	switch_file_t *audio_file = NULL;
	CURL *curl_handle = NULL;
	switch_curl_slist_t *headers = NULL;
	switch_CURLcode httpRes;
	char *body = NULL;
	char param_b64[1024] = { 0 };
	char cur_time[20] = { 0 };
	char check_sum[SWITCH_MD5_DIGEST_STRING_SIZE] = { 0 };
	char buf[2048] = { 0 };

	if (!text || !*text)
		return SWITCH_STATUS_FALSE;

	if (globals.cache_audio) {
		switch_md5_string(check_sum, text, strlen(text));
		sprintf(buf, "%s/%s.wav", globals.cache_dir, check_sum);
		if (switch_file_open(&audio_file, buf, SWITCH_FOPEN_READ | SWITCH_FOPEN_BINARY, SWITCH_FPROT_OS_DEFAULT,
							 sh->memory_pool) == SWITCH_STATUS_SUCCESS &&
			file_get_mtime(audio_file) + globals.cache_expire * 1000 * 1000 > switch_micro_time_now()) {
			switch_size_t len = switch_file_get_size(audio_file);
			if (len > 0) {
				if (!xfy->audio_buffer) {
					switch_buffer_create_dynamic(&xfy->audio_buffer, XFY_BLOCK_SIZE, len, 0);
					switch_assert(xfy->audio_buffer);
				}

				if (xfy->audio_buffer) {
					len = sizeof(buf);
					while (switch_file_read(audio_file, (void *)buf, &len) == SWITCH_STATUS_SUCCESS) {
						switch_buffer_write(xfy->audio_buffer, buf, len);
						len = sizeof(buf);
					}

					if (switch_buffer_inuse(xfy->audio_buffer) > sizeof(wave_pcm_hdr)) {
						// Trim wave header
						switch_buffer_toss(xfy->audio_buffer, sizeof(wave_pcm_hdr));

						switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "TTS read %d bytes from cache\n",
										  switch_buffer_inuse(xfy->audio_buffer));
						return SWITCH_STATUS_SUCCESS;
					}
				}
			}
		}

		if (audio_file) {
			switch_file_close(audio_file);
			audio_file = NULL;
		}
	}

	curl_handle = switch_curl_easy_init();
	if (!curl_handle) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "switch_curl_easy_init() failure\n");
		return SWITCH_STATUS_FALSE;
	}

	sprintf(buf, "{\"aue\":\"raw\",\"auf\":\"audio/L16;rate=%d\",\"voice_name\":\"%s\",\"engine_type\":\"intp65\"}",
		sh->native_rate,
		xfy->voice_name);
	switch_b64_encode((unsigned char*)buf, strlen(buf), (unsigned char*)param_b64, sizeof param_b64);

	sprintf(cur_time, "%lld", switch_time_now()/1000000);
	sprintf(buf, "%s%s%s", globals.api_key, cur_time, param_b64);
	switch_md5_string(check_sum, (void *)buf, strlen(buf));

	sprintf(buf, "X-CurTime: %s", cur_time);
	headers = switch_curl_slist_append(headers, buf);
	sprintf(buf, "X-Param: %s", param_b64);
	headers = switch_curl_slist_append(headers, buf);
	sprintf(buf, "X-Appid: %s", globals.app_id);
	headers = switch_curl_slist_append(headers, buf);
	sprintf(buf, "X-CheckSum: %s", check_sum);
	headers = switch_curl_slist_append(headers, buf);
	sprintf(buf, "X-Real-Ip: %s", "127.0.0.1");
	headers = switch_curl_slist_append(headers, buf);
	sprintf(buf, "Content-Type: application/x-www-form-urlencoded; charset=utf-8");
	headers = switch_curl_slist_append(headers, buf);

	switch_curl_easy_setopt(curl_handle, CURLOPT_POST, 1);
	switch_curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1);
	switch_curl_easy_setopt(curl_handle, CURLOPT_HEADER, 1);
	switch_curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
	switch_curl_easy_setopt(curl_handle, CURLOPT_URL, globals.api_url);

	//switch_curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, postParams.c_str()); // params  
	switch_curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
	switch_curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
	switch_curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 0);
	
	memset(buf, 0, sizeof buf);
	switch_url_encode(text, buf, sizeof buf);
	body = switch_mprintf("text=%s", buf);
	switch_curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, body);
	//switch_curl_easy_setopt(curl_handle, CURLOPT_READFUNCTION, NULL);
	//switch_curl_easy_setopt(curl_handle, CURLOPT_HEADERFUNCTION, write_header_callback);
	//switch_curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, (void *)ifly);
	switch_curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_callback);
	switch_curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)xfy);

	switch_curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 3);
	switch_curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 10);
	
	xfy->getting_header = SWITCH_TRUE;
	xfy->getting_body = SWITCH_FALSE;
	xfy->got_audio = SWITCH_FALSE;
	xfy->content_len = 0;

	httpRes = switch_curl_easy_perform(curl_handle);
	//switch_curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, httpRes);
	switch_curl_easy_cleanup(curl_handle);
	switch_curl_slist_free_all(headers);
	switch_safe_free(body);

	if (httpRes != CURLE_OK) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Received HTTP error %ld \n", httpRes);
		return SWITCH_STATUS_GENERR;
	}

	if (xfy->got_audio && xfy->audio_buffer) {
		if (globals.cache_audio) {
			switch_md5_string(check_sum, text, strlen(text));
			sprintf(buf, "%s/%s.wav", globals.cache_dir, check_sum);
			if (switch_file_open(&audio_file, buf, SWITCH_FOPEN_WRITE | SWITCH_FOPEN_CREATE | SWITCH_FOPEN_TRUNCATE | SWITCH_FOPEN_BINARY, SWITCH_FPROT_OS_DEFAULT, sh->memory_pool) == SWITCH_STATUS_SUCCESS) {
				const char* ptr = NULL;
				switch_size_t size = switch_buffer_peek_zerocopy(xfy->audio_buffer, &ptr);
				// Fixed TTS's bug
				if (size > sizeof(wave_pcm_hdr))
				{
					int* psize = (int *)(ptr + sizeof(wave_pcm_hdr) - 4);
					*psize = *psize - sizeof(wave_pcm_hdr);
				}
				switch_status_t status = switch_file_write(audio_file, ptr, &size);
				if(status != SWITCH_STATUS_SUCCESS)
				{
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "switch_file_write fail(%d)\n", status);
				}
				switch_file_close(audio_file);
			}
		}

		// Trim wave header
		switch_buffer_toss(xfy->audio_buffer, sizeof(wave_pcm_hdr));
	}

	return SWITCH_STATUS_SUCCESS;
}

static void xfy_speech_flush_tts(switch_speech_handle_t *sh)
{
	xfy_t *ifly = (xfy_t *) sh->private_info;

	if (ifly->audio_buffer) {
		switch_buffer_zero(ifly->audio_buffer);
	}
}

static switch_status_t xfy_speech_read_tts(switch_speech_handle_t *sh, void *data, size_t *datalen, switch_speech_flag_t *flags)
{
	xfy_t *xfy = (xfy_t *)sh->private_info;
	size_t bytes_read;

	if (xfy->audio_buffer && (bytes_read = switch_buffer_read(xfy->audio_buffer, data, *datalen))) {
		*datalen = bytes_read;
		return SWITCH_STATUS_SUCCESS;
	}

	return SWITCH_STATUS_FALSE;
}

static void xfy_text_param_tts(switch_speech_handle_t *sh, char *param, const char *val)
{

}

static void xfy_numeric_param_tts(switch_speech_handle_t *sh, char *param, int val)
{

}

static void xfy_float_param_tts(switch_speech_handle_t *sh, char *param, double val)
{

}

static switch_status_t load_config(void)
{
	char *cf = "xfytts.conf";
	switch_xml_t cfg, xml = NULL, param, settings;
	switch_status_t status = SWITCH_STATUS_SUCCESS;

	/* Set defaults */
	//globals.no_input_timeout = 5000;

	if (!(xml = switch_xml_open_cfg(cf, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Open of %s failed\n", cf);
		status = SWITCH_STATUS_FALSE;
		goto done;
	}

	if ((settings = switch_xml_child(cfg, "settings"))) {
		for (param = switch_xml_child(settings, "param"); param; param = param->next) {
			char *var = (char *)switch_xml_attr_soft(param, "name");
			char *val = (char *)switch_xml_attr_soft(param, "value");
			if (!strcasecmp(var, "cache-audio")) {
				globals.cache_audio = switch_true(val);
			}
			else if (!strcasecmp(var, "cache-dir")) {
				globals.cache_dir = switch_core_strdup(globals.pool, val);
			}
			else if (!strcasecmp(var, "cache-expire")) {
				globals.cache_expire = atoi(val);
			}
			else if (!strcasecmp(var, "api-url")) {
				globals.api_url = switch_core_strdup(globals.pool, val);
			}
			else if (!strcasecmp(var, "app-id")) {
				globals.app_id = switch_core_strdup(globals.pool, val);
			}
			else if (!strcasecmp(var, "api-key")) {
				globals.api_key = switch_core_strdup(globals.pool, val);
			}
		}
	}

	if (globals.cache_audio) {
		if (!globals.cache_dir) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Missing setting cache-dir\n");
			status = SWITCH_STATUS_FALSE;
		}
		else {
			if (switch_dir_make_recursive(globals.cache_dir, SWITCH_DEFAULT_DIR_PERMS, globals.pool) != SWITCH_STATUS_SUCCESS) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Fail to make cache directory\n"); 
				status = SWITCH_STATUS_FALSE;
			}
		}

		if (globals.cache_expire < 300) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Cache expire time less than 300s\n");
			status = SWITCH_STATUS_FALSE;
		}
	}

	if (!globals.api_url) {
		globals.api_url = switch_core_strdup(globals.pool, "http://api.xfyun.cn/v1/service/v1/tts");
	}

	if (!globals.app_id || !globals.api_key) {
		status = SWITCH_STATUS_FALSE;
	}

done:
	if (xml) {
		switch_xml_free(xml);
	}

	return status;
}

static void do_load(void)
{
	switch_mutex_lock(MUTEX);
	load_config();
	switch_mutex_unlock(MUTEX);
}

static void event_handler(switch_event_t *event)
{

}

SWITCH_MODULE_LOAD_FUNCTION(mod_xfytts_load)
{
	switch_speech_interface_t *speech_interface;

	switch_mutex_init(&MUTEX, SWITCH_MUTEX_NESTED, pool);

	globals.pool = pool;

	do_load();

	if ((switch_event_bind_removable(modname, SWITCH_EVENT_RELOADXML, NULL, event_handler, NULL, &NODE) != SWITCH_STATUS_SUCCESS)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't bind!\n");
	}

	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
	speech_interface = switch_loadable_module_create_interface(*module_interface, SWITCH_SPEECH_INTERFACE);
	speech_interface->interface_name = "xfytts";
	speech_interface->speech_open = xfy_speech_open;
	speech_interface->speech_close = xfy_speech_close;
	speech_interface->speech_feed_tts = xfy_speech_feed_tts;
	speech_interface->speech_read_tts = xfy_speech_read_tts;
	speech_interface->speech_flush_tts = xfy_speech_flush_tts;
	speech_interface->speech_text_param_tts = xfy_text_param_tts;
	speech_interface->speech_numeric_param_tts = xfy_numeric_param_tts;
	speech_interface->speech_float_param_tts = xfy_float_param_tts;

	/* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_xfytts_shutdown)
{
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
