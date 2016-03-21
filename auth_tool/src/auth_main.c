#include "auth.h"


#define DRV_VERSION	"0.1.1"
#define DRV_DESC	"auth driver"
#define AUTH_USER_INFO_DEV	("/dev/auth_user_info")

static int s_dev_fd = -1;


/**************************CONFIG_PARSING*********************************/
/*config verify*/
static int auth_nxjson_verify(const nx_json *js_root)
{
	int i;
	const nx_json *js;

	if (js_root->length < 0) 
	{
		AUTH_ERROR("nxjson bug, js.length < 0: %d\n", js_root->length);
		return -1;
	}

	switch (js_root->type) {
	case NX_JSON_ARRAY:
	case NX_JSON_OBJECT:
		{
			i = 0;
			for (js = js_root->child; js != NULL; js = js->next) 
			{
				i++;
				if (auth_nxjson_verify(js) != 0)
					return -1;
			}
			if (i != js_root->length) 
			{
				AUTH_ERROR("nxjson bug, js.length mismatch: %d/%d\n",
					i, js_root->length);
				return -1;
			}
			break;
		}
	default:
		// TODO: check other type
		break;
	}

	return 0;
}


static int auth_json_integer_map(uint32_t *res, const nx_json *j_integer,
	const char *name, uint32_t min, uint32_t max)
{
	*res = 0;

	if (j_integer->type == NX_JSON_NULL) 
	{
		AUTH_INFO("%s not set.\n", name);
		return 0;
	}

	if (j_integer->type != NX_JSON_INTEGER) 
	{
		AUTH_ERROR("%s is not integer.\n", name);
		return -1;
	}

	if (j_integer->int_value < min || j_integer->int_value > max) 
	{
		AUTH_ERROR("%s == %ld, out of range: [%u, %u].\n",
			name, j_integer->int_value, min, max);
		return -1;
	}

	*res = j_integer->int_value;
	return 0;
}


static int auth_json_string_map(char **res, const nx_json *j_string,
	const char *name, int max_length)
{
	int len = 0;
	
	*res = NULL;
	if (j_string->type == NX_JSON_NULL) 
	{
		AUTH_INFO("%s not set.\n", name);
		len = 0;
		goto copy;
	}

	if (j_string->type != NX_JSON_STRING) 
	{
		AUTH_ERROR("%s is not string.\n", name);
		return UGW_FAILED;
	}

	len = (int)strlen(j_string->text_value);
	if (len > max_length) 
	{
		AUTH_ERROR("%s.length == %d, out of range: [0, %d].\n",
			name, len, max_length);
		return UGW_FAILED;
	}

copy:
	*res = AUTH_NEW_N((len + 1), char);
	if (*res == NULL) 
	{
		AUTH_ERROR("%s.length == %d, out of memory\n", name, len);
		return UGW_FAILED;
	}
	memcpy(*res, j_string->text_value, len);
	(*res)[len] = 0;
	return UGW_SUCCESS;
}


static int auth_json_array_map(
	void **res,
	int *nr_res,
	const nx_json *j_array,
	const char *name,
	int max_length,
	int elem_size,
	int (* elem_ctor)(void *elem, const nx_json *js),
	void (* elem_dtor)(void *elem))
{
	const nx_json *js = NULL;
	char *array = NULL;
	int i = 0;

	*res = NULL;
	*nr_res = 0;

	if (j_array->type == NX_JSON_NULL) 
	{
		AUTH_INFO("%s not set.\n", name);
		return 0;
	}

	if (j_array->type != NX_JSON_ARRAY) 
	{
		AUTH_ERROR("%s is not array.\n", name);
		return -1;
	}

	if (j_array->length > max_length) 
	{
		AUTH_ERROR("%s.length == %d, out of range: [0, %d].\n",
			name, j_array->length, max_length);
		return -1;
	}

	if (j_array->length == 0) 
	{
		AUTH_INFO("%s is empty.\n", name);
		return 0;
	}

	array = AUTH_NEW_N(elem_size * j_array->length, char);
	if (array == NULL) 
	{
		AUTH_ERROR("%s.length == %d, out of memory.\n", name, j_array->length);
		return -1;
	}

	for (js = j_array->child; js != NULL; js = js->next, i++) 
	{
		if (elem_ctor(array + i * elem_size, js) != 0) 
		{
			AUTH_ERROR("%s[%d] init failed, total: %d.\n", name, i, j_array->length);
			if (elem_dtor != NULL) 
			{
				while (--i >= 0) 
				{
					elem_dtor(array + i * elem_size);
				}
			}
			free(array);
			return -1;
		}
	}

	*res = array;
	*nr_res = j_array->length;
	return 0;

}


#define auth_json_array_map(res, nr_res, j_array, name, max_length, elem_type, ctor, dtor) \
	((void)(*(res) == (elem_type *)NULL), \
		(void)((ctor) == (int (*)(elem_type *, const nx_json *))NULL), \
		(void)((dtor) == (void (*)(elem_type *))NULL), \
		auth_json_array_map((void **)(res), (nr_res), (j_array), \
			(name), (max_length), sizeof(elem_type), \
			(int (*)(void *, const nx_json *))(ctor), \
			(void (*)(void *))(dtor))) 


/*
*Notice:the ip-value stored as host order, which may be big endian or small endian.
*We can't make any assume to the order of current host.
*/
static int auth_str_to_ip(const char *str, uint32_t *ip)
{
	uint32_t a,b,c,d;
	char tmp;
	if (sscanf(str, "%u.%u.%u.%u %c", &a, &b, &c, &d, &tmp) != 4 ||
		a > 255 || b > 255 || c > 255 || d > 255) 
	{
		*ip = 0;
		return -1;
	}

	*ip = (a << 24) | (b << 16) | (c << 8) | d;
	return 0;
}


/*
*convertting mac str, which format is "XX:XX:XX:XX:XX:XX", to mac_bytes which consist of six bytes.
*for example, "01:AB:DE:FF:90:38" TO "01abdeff9038" 
*/
static unsigned char* convert_addrstr_to_byte(char* addr, char* dst)
{
	int i = 0;
	char separator = ':';

    for (i = 0; i < 6; ++i)
    {
        unsigned int inum = 0;
        char ch;

        ch = tolower(*addr++);

        if ((ch < '0' || ch > '9') && (ch < 'a' || ch > 'f')) {
            return NULL;
        }

        inum = isdigit (ch)?(ch - '0'):(ch - 'a' + 10);
        ch = tolower(*addr);

        if ((i < 5 && ch != separator) ||  (i == 5 && ch != '\0' && !isspace(ch))) {
                ++addr;
                if ((ch < '0' || ch > '9') && (ch < 'a' || ch > 'f')) {
                     return NULL;
                 }

                inum <<= 4;
                inum += isdigit(ch) ? (ch - '0') : (ch - 'a' + 10);
                ch = *addr;

                if (i < 5 && ch != separator) {
                    return NULL;
                }
        }

        dst[i] = (unsigned char)inum;
        ++addr;
    }
    return dst;
}

/***************************************update_user_parsing**************************************/
static void auth_update_user_cleanup(struct user_info *user)
{
	if (user) {
		memset(user, 0, sizeof(struct user_info));
	}
}


static int auth_update_user_init(struct user_info *user, const nx_json *js)
{
	char *mac_str = NULL;
	memset(user, 0, sizeof(struct user_info));
	if (auth_json_string_map(&mac_str,
			nx_json_get(js, "UserMac"),
			"config.UpdateUserStatus[n].UserMac",
			MAC_STR_SIZE) != 0) 
	{
		goto fail;
	}

	if (convert_addrstr_to_byte(mac_str, user->mac) == NULL)
	{
		goto fail;
	}

	if (auth_json_integer_map(&user->status, 
		nx_json_get(js, "Action"),  
		"config.UpdateUserStatus[n].Action",
		0, 1) != 0)
	{
		goto fail;
	}

	if (mac_str) 
	{
		free(mac_str);
	}
	return 0;

fail:
	if (mac_str) 
	{
		free(mac_str);
	}
	auth_update_user_cleanup(user);
	return -1;
}


static int do_auth_update_user_parsing(struct user_info **users, uint32_t *nc_user, const nx_json *js)
{
	if (auth_json_array_map(users, nc_user, js, "config.UpdateUserStatus", AUTH_USER_COUNT_MAX, 
			struct user_info, auth_update_user_init, auth_update_user_cleanup) != 0) 
	{
		goto fail;
	}
	return 0;
fail:
	return -1;
}


/***************************************ip_rule_parsing**************************************/
static void auth_interface_cleanup(struct auth_if_info *if_info)
{
	free(if_info->if_name);
	if_info->if_name = NULL;
	memset(if_info, 0, sizeof(struct auth_if_info));
}


static int auth_interface_init(struct auth_if_info *if_info, const nx_json *js)
{
	memset(if_info, 0, sizeof(struct auth_if_info));

	if (auth_json_string_map(&if_info->if_name,
			nx_json_get(js, "InterfaceName"),
			"config.InterfaceInfo[n].InterfaceName",
			IF_NAME_MAX) != 0) 
	{
		goto fail;
	}

	if (auth_json_integer_map(&if_info->type, 
		nx_json_get(js, "InterfaceType"),  
		"config.InterfaceInfo[n].InterfaceType",
		0, NET_IF_TYPE_NUM) != 0)
	{
		goto fail;
	}

	return 0;

fail:
	auth_interface_cleanup(if_info);
	return -1;
}


static int do_auth_interface_parsing(struct auth_if_info **if_infos, uint32_t *nc_if, const nx_json *js)
{
	if (auth_json_array_map(if_infos, nc_if, js, "config.InterfaceInfo", AUTH_RULE_COUNT_MAX, 
			struct auth_if_info, auth_interface_init, auth_interface_cleanup) != 0) 
	{
		goto fail;
	}
	return 0;
fail:
	return -1;
}


static void auth_url_cleanup(struct auth_url_info *url_info)
{
	free(url_info->uri);
	free(url_info->host);
	url_info->uri = NULL;
	url_info->host = NULL;
	memset(url_info, 0, sizeof(struct auth_url_info));
}


static int auth_url_init(struct auth_url_info *url_info, const nx_json *js)
{
	memset(url_info, 0, sizeof(struct auth_url_info));

	if (auth_json_string_map(&url_info->uri,
			nx_json_get(js, "uri"),
			"config.urlInfos[n].uri",
			BYPASS_URI_LEN) != 0) 
	{
		goto fail;
	}

	if (auth_json_string_map(&url_info->host,
			nx_json_get(js, "host"),
			"config.urlInfos[n].host",
			BYPASS_HOST_LEN) != 0) 
	{
		goto fail;
	}

	if (auth_json_integer_map(&url_info->action, 
		nx_json_get(js, "action"),  
		"config.urlInfos[n].action",
		0, 1) != 0)
	{
		goto fail;
	}

	return 0;

fail:
	auth_url_cleanup(url_info);
	return -1;
}

static int do_auth_url_parsing(struct auth_url_info **url_infos, uint32_t *nc_url, const nx_json *js)
{
	if (auth_json_array_map(url_infos, nc_url, js, "config.urlInfos", AUTH_RULE_COUNT_MAX, 
			struct auth_url_info, auth_url_init, auth_url_cleanup) != 0) 
	{
		goto fail;
	}
	return 0;
fail:
	return -1;
}


/***************************************ip_rule_parsing**************************************/
static int auth_ip_range_init(struct ip_range *range, const nx_json *js)
{
	int ret = -1;
	char *start_ip = NULL, *end_ip = NULL;

	memset(range, 0, sizeof(struct ip_range));
	if (auth_json_string_map(&start_ip, nx_json_get(js, "Start"), 
			"config.AuthPolicy[n].IpRange[n].Start", IPV4_STR_LEN_MAX) != 0)
	{
		goto fail;
	}
	if (auth_str_to_ip(start_ip, &range->min) != 0)
	{
		goto fail;
	}

	if (auth_json_string_map(&end_ip, nx_json_get(js, "End"), 
			"config.AuthPolicy[n].IpRange[n].End", IPV4_STR_LEN_MAX) != 0)
	{
		goto fail;
	}

	if (auth_str_to_ip(end_ip, &range->max) != 0)
	{
		goto fail;
	}
	ret = 0;	
fail:
	if (start_ip)
	{
		free(start_ip);
	}
	if (end_ip)
	{
		free(end_ip);
	}
	return ret;
}


static void auth_ip_rule_cleanup(struct auth_ip_rule *rule)
{
	free(rule->name);
	rule->name = NULL;
	free(rule->ip_ranges);
	rule->ip_ranges = NULL;
	memset(rule, 0, sizeof(struct auth_ip_rule));
}


static int auth_ip_rule_init(struct auth_ip_rule *rule, const nx_json *js)
{
	memset(rule, 0, sizeof(struct auth_ip_rule));


	if (auth_json_string_map(&rule->name,
			nx_json_get(js, "AuthPolicyName"),
			"config.Rules[n].AuthPolicyName",
			AUTH_RULE_NAME_MAX) != 0) 
	{
		goto fail;
	}

	if (auth_json_integer_map(&rule->type, 
		nx_json_get(js, "AuthType"),  
		"config.AuthPolicy[n].AuthType",
		0, IP_RULE_TYPE_NUM) != 0)
	{
		goto fail;
	}

	if (auth_json_integer_map(&rule->priority, 
		nx_json_get(js, "Priority"),  
		"config.AuthPolicy[n].Priority",
		0, AUTH_IP_RULE_MAX_PRIORITY) != 0)
	{
		goto fail;
	}

	if (auth_json_integer_map(&rule->timeout, 
		nx_json_get(js, "Timeout"),  
		"config.AuthPolicy[n].timeout",
		0, 65535) != 0)
	{
		goto fail;
	}

	if (auth_json_integer_map(&rule->enable, 
		nx_json_get(js, "Enable"),  
		"config.AuthPolicy[n].Enable",
		0, 1) != 0)
	{
		goto fail;
	}

	if (auth_json_array_map(&rule->ip_ranges, &rule->nc_ip_range,
			nx_json_get(js, "IpRange"),
			"config.AuthPolicy[n].IpRange",
			AUTH_IP_RANGE_COUNT_MAX,
			struct ip_range, auth_ip_range_init, NULL) != 0) 
	{
		goto fail;
	}

	return 0;

fail:
	auth_ip_rule_cleanup(rule);
	return -1;
}


static int do_auth_ip_rule_parsing(struct auth_ip_rule **rules, uint32_t *nc_rule, const nx_json *js)
{
	if (auth_json_array_map(rules, nc_rule, js, "config.AuthPolicy", AUTH_RULE_COUNT_MAX, 
			struct auth_ip_rule, auth_ip_rule_init, auth_ip_rule_cleanup) != 0) 
	{
		goto fail;
	}
	return 0;
fail:
	return -1;
}


/***************************************auth_option_parsing**************************************/
static int do_auth_option_parsing(struct auth_options *auth_option, const nx_json *js)
{
	memset(auth_option, 0, sizeof(struct auth_options));

	if (auth_json_integer_map(&auth_option->user_check_intval, 
		nx_json_get(js, "CheckOffline"),  
		"config.GlobaleAuthOption.CheckOffline",
		USR_CHECK_INTVAL_MIN, USR_CHECK_INTVAL_MAX) != 0)
	{
		goto fail;
	}

	if (auth_json_string_map(&auth_option->redirect_url,
		nx_json_get(js, "RedirectUrl"),
		"config.GlobaleAuthOption.RedirectUrl",
		REDIRECT_URL_MAX) != 0) 
	{
		goto fail;
	}

	if (auth_json_string_map(&auth_option->redirect_title,
		nx_json_get(js, "PushTitle"),
		"config.GlobaleAuthOption.PushTitle",
		REDIRECT_TITLE_MAX) != 0) 
	{
		goto fail;
	}

	if (auth_json_integer_map(&auth_option->bypass_enable, 
		nx_json_get(js, "GlobalBypass"),  
		"config.GlobaleAuthOption.GlobalBypass",
		0, 1) != 0)
	{
		goto fail;
	}

	return 0;
fail:
	return -1;
}


/*parsing config divided into two parts:auth options and auth rules.*/
static int do_auth_config_parsing(struct auth_global_config *config, const nx_json *js)
{
	const nx_json *js_elem = NULL;

	memset(config, 0, sizeof(struct auth_global_config));
	if (js->type != NX_JSON_OBJECT) 
	{
		AUTH_ERROR("config is not object\n");
		goto fail;
	}

	/*parse auth option*/
	js_elem = nx_json_get(js, "GlobaleAuthOption");
	if (js_elem->type != NX_JSON_NULL) {
		if (do_auth_option_parsing(&config->auth_opt, js_elem) == UGW_SUCCESS) {
			config->update_auth_opt = 1;
		}
		else {
			goto fail;
		}
	}

	/*parse auth rules*/
	js_elem = nx_json_get(js, "AuthPolicy");
	if (js_elem->type != NX_JSON_NULL) {
		if (do_auth_ip_rule_parsing(&config->ip_rules, &config->nc_ip_rule, js_elem) == UGW_SUCCESS) {
			config->update_ip_rules = 1;
		}
		else {
			goto fail;
		}
	}

	/*parse interface*/
	js_elem = nx_json_get(js, "InterfaceInfo");
	if (js_elem->type != NX_JSON_NULL) {
		if (do_auth_interface_parsing(&config->if_infos, &config->nc_if, js_elem) == UGW_SUCCESS) {
			config->update_if_infos = 1;
		}
		else {
			goto fail;
		}
	}


	/*parse urls*/
	js_elem = nx_json_get(js, "BypassUrl");
	if (js_elem->type != NX_JSON_NULL) {
		if (do_auth_url_parsing(&config->url_infos, &config->nc_url, js_elem) == UGW_SUCCESS) {
			config->update_url_infos = 1;
		}
		else {
			goto fail;
		}
	}

	/*parse user status*/
	js_elem = nx_json_get(js, "UpdateUserStatus");
	if (js_elem->type != NX_JSON_NULL) {
		if (do_auth_update_user_parsing(&config->users, &config->nc_user, js_elem) == UGW_SUCCESS) {
			config->update_user = 1;
		}
		else {
			goto fail;
		}
	}

	/*get_all_user info*/
	js_elem =  nx_json_get(js, "GetAllUser");
	if (js_elem->type != NX_JSON_NULL) {
		if (js_elem->int_value) {
			config->get_all_user = 1;
		}
		else {
			config->get_all_user = 0;
		}
	}
	
	return UGW_SUCCESS;

fail:
	return UGW_FAILED;
}


static void auth_ip_rule_dump(struct auth_ip_rule *rule)
{
	int i;
	AUTH_INFO("~~~~~~~~~ AUTH RULE [%s] ~~~~~~~~~\n", rule->name);
	AUTH_INFO("type: %u.\n", rule->type);
	AUTH_INFO("enable: %u.\n", rule->enable);
	AUTH_INFO("ip range count: %u.\n", rule->nc_ip_range);
	for (i = 0; i < rule->nc_ip_range; i++)
	{
		struct ip_range *range = &rule->ip_ranges[i];
		AUTH_INFO("ip range %d: ["IPQUAD_FMT","IPQUAD_FMT"].\n", i, 
					HIPQUAD(range->min), HIPQUAD(range->max));
	}
}


static void auth_if_info_dump(struct auth_if_info *if_info)
{
	AUTH_INFO("~~~~~~~~~ AUTH_INTERFACE BEGIN~~~~~~~~~\n");
	AUTH_INFO("Interface Type: %d.\n", if_info->type);
	AUTH_INFO("Interface Name: %s.\n", if_info->if_name);
	AUTH_INFO("~~~~~~~~~ AUTH_INTERFACE END~~~~~~~~~\n");
}

static void auth_url_info_dump(struct auth_url_info *url_info)
{
	AUTH_INFO("~~~~~~~~~ AUTH_URL BEGIN~~~~~~~~~\n");
	AUTH_INFO("BYPASS ACTION: %d.\n", url_info->action);
	AUTH_INFO("BYPASS URI: %s.\n", url_info->uri);
	AUTH_INFO("BYPASS HOST: %s.\n", url_info->host);
	AUTH_INFO("~~~~~~~~~ AUTH_URL END~~~~~~~~~\n");
}

static void auth_option_dump(struct auth_options *option)
{
	AUTH_INFO("~~~~~~~~~ AUTH OPTION BEGIN~~~~~~~~~\n");
	AUTH_INFO("usr_check_intval: %u.\n", option->user_check_intval);
	AUTH_INFO("redirect_url: %s.\n", option->redirect_url);
	AUTH_INFO("redirect_title: %s.\n", option->redirect_title);
	AUTH_INFO("bypass_enable: %u.\n", option->bypass_enable);
	AUTH_INFO("~~~~~~~~~ AUTH OPTION END~~~~~~~~~\n\n");
}

static void auth_user_status_dump(struct user_info *user)
{
	AUTH_INFO("~~~~~~~~~ AUTH USER STATUS BEGIN~~~~~~~~~\n");
 	AUTH_INFO("UserMac:%02X:%02X:%02X:%02X:%02X:%02X.\n", 
				user->mac[0],  user->mac[1],  user->mac[2],
				user->mac[3],  user->mac[4],  user->mac[5]);
	AUTH_INFO("Action: %d.\n", user->status);
	AUTH_INFO("~~~~~~~~~ AUTH USER STATUS END~~~~~~~~~\n\n");
}


static void auth_config_dump(struct auth_global_config *config)
{
	int i;

	AUTH_INFO("--------------- AUTH CONFIG ---------------\n");
	if (config->update_auth_opt) {
		auth_option_dump(&config->auth_opt);
	}

	if (config->update_ip_rules) {
		for (i = 0; i < config->nc_ip_rule; i++) {
			auth_ip_rule_dump(&config->ip_rules[i]);
		}
	}

	if (config->update_if_infos) {
		for (i = 0; i < config->nc_if; i++) {
			auth_if_info_dump(&config->if_infos[i]);
		}
	}


	if (config->update_url_infos) {
		for (i = 0; i < config->nc_url; i++) {
			auth_url_info_dump(&config->url_infos[i]);
		}
	}

	if (config->update_user) {
		for (i = 0; i < config->nc_user; i++) {
			auth_user_status_dump(&config->users[i]);
		}
	}


	if (config->get_all_user) {
		AUTH_INFO("GetAllUser:%d.\n", config->get_all_user);
	}
	AUTH_INFO("------------------------------------------\n");
}


/*parse config:Firstly, checking valid of config, and then parsing config, dumpping config lastly.*/
static int auth_config_parsing(struct auth_global_config *config, const char *json, size_t size)
{
	int ret = -1;
	char *json_data = NULL;
	const nx_json *js = NULL;

	memset(config, 0, sizeof(struct auth_global_config));
	json_data = AUTH_NEW_N((size + 1), char);
	if (json_data == NULL) 
	{
		AUTH_ERROR("auth_config_parsing failed: out of memory.\n");
		goto out;
	}
	memset(json_data, 0, (size + 1));
	memcpy(json_data, json, size);

	js = nx_json_parse_utf8(json_data);
	if (js == NULL) 
	{
		AUTH_ERROR("config parse failed.\n");
		goto out;
	}

	if (auth_nxjson_verify(js) != 0) 
	{
		AUTH_ERROR("nxjson verify failed.\n");
		goto out;
	}

	if (do_auth_config_parsing(config, js) != 0) 
	{
		AUTH_ERROR("do_auth_config_parsing failed.\n");
		goto out;
	}

#if DEBUG_ENABLE
	auth_config_dump(config);
#endif

	ret = 0;
out:
	if (js != NULL) 
	{
		nx_json_free(js);
	}
	if (json_data != NULL) 
	{
		free(json_data);
	}	
	return ret;
}


static void auth_config_free(struct auth_global_config *auth_config)
{
	int i = 0;
	if (auth_config == NULL) {
		return;
	}
	if (auth_config->ip_rules) {
		for (i = 0; i < auth_config->nc_ip_rule; i++) {
			free(auth_config->ip_rules[i].ip_ranges);
			auth_config->ip_rules[i].ip_ranges = NULL;
		}
		free(auth_config->ip_rules);
		auth_config->ip_rules = NULL;
	}

	if (auth_config->if_infos) {
		for (i = 0; i < auth_config->nc_if; i++) {
			free(auth_config->if_infos[i].if_name);
			auth_config->if_infos[i].if_name = NULL;
		}
		free(auth_config->if_infos);
		auth_config->if_infos = NULL;
	}

	if (auth_config->users) {
		free(auth_config->users);
		auth_config->users = NULL;
	}

	if (auth_config->auth_opt.redirect_title) {
		free(auth_config->auth_opt.redirect_title);
		auth_config->auth_opt.redirect_title = NULL;
	}

	if (auth_config->auth_opt.redirect_url) {
		free(auth_config->auth_opt.redirect_url);
		auth_config->auth_opt.redirect_url = NULL;
	}
}


static void auth_config_clear(struct auth_global_config *auth_config)
{
	if (auth_config == NULL) {
		return;
	} 
	memset(auth_config, 0, sizeof(struct auth_global_config));
	auth_config->ip_rules = NULL;
	auth_config->if_infos = NULL;
	auth_config->users = NULL;
}


/**********************************commit_to_kernel************************/
static char *safe_strncpy(char *dst, const char *src, const size_t len)
{
	assert(dst);
	assert(src);
	if (strlen(src) >= len)
	{
		strncpy(dst, src, len - 1);
		dst[len - 1] = '\0';
	}
	else
	{
		strncpy(dst, src, strlen(src));
		dst[strlen(src)] = '\0';
	}
	return NULL;
}

static int32_t ioc_obj_pars_check(enum ARG_TYPE_E arg_type, uint16_t *real_nc)
{
	int32_t  ret = UGW_SUCCESS;
	switch (arg_type) {
		case AUTH_RULE:
			ret = UGW_SUCCESS;
			break;

		case AUTH_OPTION:
			*real_nc = 1;
			ret = UGW_SUCCESS;
			break;

		case USER_SSTAT:
			if (*real_nc == 0) {
				ret = UGW_FAILED;
			}
			else {
				ret = UGW_SUCCESS;
			}
			break;

		case USER_GSTAT:	
			*real_nc = 1;
			ret = UGW_SUCCESS;

		case NET_IF_INFO:
			ret = UGW_SUCCESS;
			break;

		case BYPASS_URL_INFO:
			ret = UGW_SUCCESS;
			break;

		default:
			ret = UGW_FAILED;
			break;
	}
	return ret;
}


struct auth_ioc_arg *create_ioc_obj(enum ARG_TYPE_E arg_type, uint16_t nc_element)
{
	struct auth_ioc_arg *ioc_arg = NULL;
	uint16_t header_len = 0, body_len = 0, unit_len = 0, real_nc = 0, total_len = 0, sub_header = 0;

	real_nc = nc_element;
	if (ioc_obj_pars_check(arg_type, &real_nc) == UGW_FAILED)
	{
		AUTH_ERROR("arg_type(%d)  is invalid.", arg_type);
		return NULL;
	}
	header_len = sizeof(struct auth_ioc_arg);
	switch (arg_type) {
		case AUTH_RULE:
			if (nc_element) {
				sub_header = sizeof(struct ioc_auth_ip_rule);
				unit_len = sizeof(struct ip_range) * nc_element;
				real_nc = 1;
			}
			else {
				unit_len = sizeof(struct ip_range);
			}
			break;

		case AUTH_OPTION:
			unit_len = sizeof(struct ioc_auth_options);
			break;

		case USER_GSTAT:
			unit_len = sizeof(struct user_stat_assist);
			break;

		case USER_SSTAT:
			unit_len = sizeof(struct user_info);
			break;

		case NET_IF_INFO: 
			unit_len = sizeof(struct ioc_auth_if_info);
			break;

		case BYPASS_URL_INFO:
			unit_len = sizeof(struct ioc_auth_url_info);
			break;

		default:
			unit_len = 0;
			break;
	}
	if (unit_len == 0) {
		AUTH_ERROR("Arg_type[%d] is invalid type.\n", arg_type);
		return NULL;
	}
	body_len = real_nc * unit_len;
	ioc_arg = (struct auth_ioc_arg*)malloc(header_len + sub_header + body_len);
	if (ioc_arg == NULL) {
		AUTH_ERROR("No memory.\n");
		return NULL;
	}
	memset(ioc_arg, 0, total_len);
	ioc_arg->type = arg_type;
	ioc_arg->num = real_nc;
	ioc_arg->data_len = body_len + sub_header;
	return ioc_arg;
}


void free_ioc_obj(struct auth_ioc_arg *arg)
{
	if (arg == NULL) {
		return;
	}
	// if (arg->type == USER_GSTAT) {
	// 	struct user_stat_assit *assist = 
	// 			(struct user_stat_assist*)((void*)arg + sizeof(struct auth_ioc_arg));
	// 	if (assist->addr) {
	// 		free(assist->addr);
	// 		assist->addr = NULL;
	// 	}
	// }
	free(arg);
}


/*****************************************UPDATE_AUTH_IPRULES*******************************/
static void display_auth_ip_rule_objs(struct auth_ioc_arg *ioc_obj)
{
	assert(ioc_obj);
	void *header = NULL;
	int i = 0, j = 0, offset = 0;
	struct ioc_auth_ip_rule *ip_rule = NULL;
	struct ip_range *ranges = NULL;

	header = (void*)ioc_obj;
	offset = sizeof(struct auth_ioc_arg);

	AUTH_DEBUG("***************AUTH_IP_RULE_OBJS****************\n");
	AUTH_DEBUG("IOC_TYPE:%d\n", ioc_obj->type);
	AUTH_DEBUG("IOC_NUM:%d\n", ioc_obj->num);
	AUTH_DEBUG("DATA_LEN:%d\n", ioc_obj->data_len);
	for (i = 0; i < ioc_obj->num; i++) {
		ip_rule = (struct ioc_auth_ip_rule*)((void*)header + offset);
		AUTH_DEBUG("RULE_NAME:%s\n", ip_rule->name);
		AUTH_DEBUG("RULE_TYPE:%d\n", ip_rule->type);
		AUTH_DEBUG("RULE_ENABLE:%d\n", ip_rule->enable);
		AUTH_DEBUG("RULE_PRIORITY:%d\n", ip_rule->priority);
		AUTH_DEBUG("RULE_TIMEOUT:%d\n", ip_rule->timeout);
		AUTH_DEBUG("RULE_NC_IPRANGE:%d\n", ip_rule->nc_ip_range);
		ranges = (struct ip_range*)((void*)ip_rule + sizeof(struct ioc_auth_ip_rule));
		for (j = 0; j < ip_rule->nc_ip_range; j++) {
			AUTH_DEBUG("ip range %d: ["IPQUAD_FMT","IPQUAD_FMT"].\n", j, 
					HIPQUAD(ranges[j].min), HIPQUAD(ranges[j].max));
		}
		offset += ip_rule->nc_ip_range * sizeof(struct ip_range) + sizeof(struct ioc_auth_ip_rule);
		AUTH_DEBUG("****************************************\n\n");
	}
	AUTH_DEBUG("***************AUTH_IP_RULE_OBJ****************\n\n");
}

static int auth_rule_ip_valid_check(uint32_t min_ip, uint32_t max_ip, uint8_t type, uint8_t enable, uint8_t priority)
{
	return UGW_SUCCESS;
}


static int set_auth_ip_ranges(struct auth_ioc_arg *arg, struct auth_ip_rule *ip_rule)
{
	assert(arg);
	assert(ip_rule);
	int i = 0;
	struct ioc_auth_ip_rule *ioc_ip_rule = 
			(struct ioc_auth_ip_rule*)((void*)arg + sizeof(struct auth_ioc_arg));
	struct ip_range *ranges = (struct ip_range*)((void*)ioc_ip_rule + sizeof(struct ioc_auth_ip_rule));
	for (i = 0; i < ip_rule->nc_ip_range; i++) {
		ranges[i].min = ip_rule->ip_ranges[i].min;
		ranges[i].max = ip_rule->ip_ranges[i].max;
	}
	safe_strncpy(ioc_ip_rule->name, ip_rule->name, AUTH_RULE_NAME_MAX);
	ioc_ip_rule->type = ip_rule->type;
	ioc_ip_rule->enable = ip_rule->enable;
	ioc_ip_rule->priority = ip_rule->priority;
	ioc_ip_rule->timeout = ip_rule->timeout;
	ioc_ip_rule->nc_ip_range = ip_rule->nc_ip_range;
	return UGW_SUCCESS;
}


/*format:header[auth_ioc_arg]+{(sub_header+body):(sub_header+body)}*/
static struct auth_ioc_arg *pack_auth_ip_rule_objs(uint8_t obj_cnt,...)
{
	assert(obj_cnt >= 2);
	int i = 0;
	va_list vars;
	uint32_t data_len = 0, num = 0;
	struct auth_ioc_arg *ioc_obj = NULL, **ioc_obj_arr = NULL;
	struct ioc_auth_ip_rule *dst_sub_rule = NULL, *src_sub_rule = NULL;

	ioc_obj_arr = AUTH_NEW_N(obj_cnt, struct auth_ioc_arg*);
	if (ioc_obj_arr == NULL) {
		goto NO_MEM;
	}
	va_start(vars, obj_cnt);
	for (i = 0; i < obj_cnt; i++)
	{
		ioc_obj_arr[i] = va_arg(vars, struct auth_ioc_arg*);
		if (ioc_obj_arr[i]) {
			data_len += ioc_obj_arr[i]->data_len;
			num += ioc_obj_arr[i]->num;
		}
	}
	va_end(vars);
	ioc_obj = (struct auth_ioc_arg*)AUTH_NEW_N((sizeof(struct auth_ioc_arg) + data_len), char);
	if (ioc_obj == NULL) {
		goto NO_MEM;
	}
	ioc_obj->type = AUTH_RULE;
	ioc_obj->num = num;
	ioc_obj->data_len = data_len;
	dst_sub_rule = (struct ioc_auth_ip_rule*)((void*)ioc_obj + sizeof(struct auth_ioc_arg));
	for (i = 0; i < obj_cnt; i++) {
		if (ioc_obj_arr[i] == NULL) {
			continue;
		}	
		src_sub_rule = 
			(struct ioc_auth_ip_rule*)((void*)ioc_obj_arr[i] + sizeof(struct auth_ioc_arg));
		memcpy(dst_sub_rule, src_sub_rule, ioc_obj_arr[i]->data_len);
		dst_sub_rule = (struct ioc_auth_ip_rule*) ((void*)dst_sub_rule + ioc_obj_arr[i]->data_len);
		free(ioc_obj_arr[i]);
	}
	free(ioc_obj_arr);
	return ioc_obj;

NO_MEM:
	if (ioc_obj_arr) {
		free(ioc_obj_arr);
	}
	return NULL;
}


int update_auth_ip_rules_to_kernel(struct auth_ip_rule *rules, uint16_t nc_rule)
{
	int i = 0, ret = UGW_SUCCESS;
 	struct auth_ioc_arg *ioc_obj = NULL, *packed_ioc_obj = NULL, **ioc_obj_arr = NULL;
 	struct ioc_auth_ip_rule *ip_rule = NULL;

 	if (rules && nc_rule) {
	 	ioc_obj_arr = AUTH_NEW_N(nc_rule, struct auth_ioc_arg*);
	 	if (ioc_obj_arr == NULL) {
	 		goto NO_MEM;
	 	}

	 	for (i = 0; i < nc_rule; i++) {
	 		ioc_obj_arr[i] = NULL;
	 	}

	 	for (i = 0; i < nc_rule; i++) {
			ioc_obj_arr[i] = create_ioc_obj(AUTH_RULE,  rules[i].nc_ip_range);
			if (ioc_obj_arr[i] == NULL) {
				goto NO_MEM;
			}
			set_auth_ip_ranges(ioc_obj_arr[i], &rules[i]);
	 	}
	 	for (i = 0; i < nc_rule; i++) {
	 		if (packed_ioc_obj) {
	 			packed_ioc_obj = pack_auth_ip_rule_objs(2, ioc_obj, ioc_obj_arr[i]);
	 			if (packed_ioc_obj == NULL) {
	 				goto NO_MEM;
	 			}
	 			ioc_obj_arr[i] = NULL;
	 			ioc_obj = packed_ioc_obj;
	 		}
	 		else {
	 			packed_ioc_obj = ioc_obj_arr[i];	/*ioc_obj_arr[0]*/
	 			ioc_obj = packed_ioc_obj;
	 		}
	 	}
 	}
 	else {
 		packed_ioc_obj = create_ioc_obj(AUTH_RULE, 0);
 		if (packed_ioc_obj == NULL) {
 			goto NO_MEM;
 		}
 	}
 #if DEBUG_ENABLE
 	display_auth_ip_rule_objs(packed_ioc_obj);
 #endif
	if (ioctl(s_dev_fd, SIOCSAUTHRULES, packed_ioc_obj) != 0) {
		AUTH_ERROR("ioctl of update ip rules failed.\n");
	}
	free_ioc_obj(packed_ioc_obj);
	free(ioc_obj_arr);
	return ret;
NO_MEM:
	if (ioc_obj_arr) {
		for (i = 0; i < nc_rule; i++) {
			if (ioc_obj_arr[i]) {
				free(ioc_obj_arr[i]);
			}
		}
		free(ioc_obj_arr);
	}
	if (ioc_obj) {
		free(ioc_obj);
	}
	return UGW_FAILED;
}


/*****************************************UPDATE_NET_IF_INFOS*******************************/
static void display_if_info_ioc_obj(struct auth_ioc_arg *ioc_obj)
{
	assert(ioc_obj);
	int i = 0;
	struct ioc_auth_if_info *if_info = 
			(struct ioc_auth_if_info*)((void*)ioc_obj + sizeof(struct auth_ioc_arg));
	AUTH_DEBUG("*************AUTH_OPTION IOC_OBJ***************\n");
	AUTH_DEBUG("IOC_TYPE:%d\n", ioc_obj->type);
	AUTH_DEBUG("IOC_NUM:%d\n", ioc_obj->num);
	AUTH_DEBUG("DATA_LEN:%d\n", ioc_obj->data_len);
	for (i = 0; i < ioc_obj->num; i++) {
		AUTH_DEBUG("Interface_Type:%d\n", if_info[i].type);
		AUTH_DEBUG("Interface_Name:%s\n", if_info[i].if_name);
	}
	AUTH_DEBUG("***********************************************\n\n");
}


static int auth_if_info_valid_check(uint8_t type, const char *if_name)
{
	return UGW_SUCCESS;
}


int set_auth_if_info(struct auth_ioc_arg *arg, uint16_t obj_id, uint8_t type, const char *if_name)
{
	assert(arg);
	struct ioc_auth_if_info *if_info = NULL;
	if (auth_if_info_valid_check(type, if_name) == UGW_FAILED) {
		return UGW_FAILED;
	}
	if (obj_id >= arg->num) {
		AUTH_ERROR("OBJ_ID(%u) >= OBJ_COUNT(%u) out of range.\n");
		return UGW_FAILED;
	}
	if_info = (struct ioc_auth_if_info*)((void*)arg + sizeof(struct auth_ioc_arg));
	if_info[obj_id].type = type;
	safe_strncpy(if_info[obj_id].if_name, if_name, IF_NAME_MAX);
	return UGW_SUCCESS;
}


int update_auth_if_infos_to_kernel(struct auth_if_info *if_infos, uint16_t nc_info)
{
	int i = 0, ret = UGW_SUCCESS;

	struct auth_ioc_arg *ioc_obj = create_ioc_obj(NET_IF_INFO, nc_info);
	if (ioc_obj == NULL) {
		AUTH_ERROR("No mem.\n");
		ret = UGW_FAILED;
		goto OUT;
	}	
	if (nc_info != 0)
	{
		for (i = 0; if_infos && i < nc_info; i++) {
			if (set_auth_if_info(ioc_obj, i, if_infos[i].type, if_infos[i].if_name) == UGW_FAILED) {
				ret = UGW_FAILED;
				goto OUT;
			}
		}
	}
#if DEBUG_ENABLE
	display_if_info_ioc_obj(ioc_obj);
#endif
	if (ioctl(s_dev_fd, SIOCSIFINFO, ioc_obj) != 0) {
		AUTH_ERROR("ioctl of set auth if_infos failed.\n");
		ret = UGW_FAILED;
		goto OUT;
	}
OUT:
	if (ioc_obj) {
		free_ioc_obj(ioc_obj);
		ioc_obj = NULL;
	}
	return ret;
}


static void display_url_info_ioc_obj(struct auth_ioc_arg *ioc_obj)
{
	assert(ioc_obj);
	int i = 0;
	struct ioc_auth_url_info *url_info = 
			(struct ioc_auth_url_info*)((void*)ioc_obj + sizeof(struct auth_ioc_arg));
	AUTH_DEBUG("*************AUTH_OPTION IOC_OBJ***************\n");
	AUTH_DEBUG("IOC_TYPE:%d\n", ioc_obj->type);
	AUTH_DEBUG("IOC_NUM:%d\n", ioc_obj->num);
	AUTH_DEBUG("DATA_LEN:%d\n", ioc_obj->data_len);
	for (i = 0; i < ioc_obj->num; i++) {
		AUTH_DEBUG("bypass_action:%d\n", url_info[i].action);
		AUTH_DEBUG("bypass_uri:%s\n", url_info[i].uri);
		AUTH_DEBUG("bypass_uri_len:%d\n", url_info[i].uri_len);
		AUTH_DEBUG("bypass_host:%s\n", url_info[i].host);
		AUTH_DEBUG("bypass_host_len:%d\n", url_info[i].host_len);
	}
	AUTH_DEBUG("***********************************************\n\n");
}


static int auth_url_info_valid_check(uint8_t action, const char *uri, const char *host)
{
	if (!uri || strlen(uri) >= BYPASS_URI_LEN) {
		AUTH_ERROR("URI INVALID.\n");
		return UGW_FAILED;
	}
	if (!host || strlen(host) >= BYPASS_HOST_LEN) {
		AUTH_ERROR("HOST INVALID.\n");
		return UGW_FAILED;
	}
	return UGW_SUCCESS;
}


int set_auth_url_info(struct auth_ioc_arg *arg, uint16_t obj_id, uint8_t action, const char *uri, const char *host)
{
	assert(arg);
	struct ioc_auth_url_info *url_info = NULL;
	if (auth_url_info_valid_check(action, uri, host) == UGW_FAILED) {
		return UGW_FAILED;
	}
	if (obj_id >= arg->num) {
		AUTH_ERROR("OBJ_ID(%u) >= OBJ_COUNT(%u) out of range.\n");
		return UGW_FAILED;
	}
	url_info = (struct ioc_auth_url_info*)((void*)arg + sizeof(struct auth_ioc_arg));
	url_info[obj_id].action = action;
	safe_strncpy(url_info[obj_id].uri, uri, BYPASS_URI_LEN);
	safe_strncpy(url_info[obj_id].host, host, BYPASS_HOST_LEN);
	url_info[obj_id].uri_len = strlen(uri);
	url_info[obj_id].host_len = strlen(host);
	return UGW_SUCCESS;
}


int update_auth_url_infos_to_kernel(struct auth_url_info *url_infos, uint16_t nc_url)
{
	int i = 0, ret = UGW_SUCCESS;

	struct auth_ioc_arg *ioc_obj = create_ioc_obj(BYPASS_URL_INFO, nc_url);
	if (ioc_obj == NULL) {
		AUTH_ERROR("No mem.\n");
		ret = UGW_FAILED;
		goto OUT;
	}	
	if (nc_url != 0)
	{
		for (i = 0; url_infos && i < nc_url; i++) {
			if (set_auth_url_info(ioc_obj, i, url_infos[i].action, url_infos[i].uri, url_infos[i].host) == UGW_FAILED) {
				ret = UGW_FAILED;
				goto OUT;
			}
		}
	}
#if DEBUG_ENABLE
	display_url_info_ioc_obj(ioc_obj);
#endif
	if (ioctl(s_dev_fd, SIOCSAUTHURLS, ioc_obj) != 0) {
		AUTH_ERROR("ioctl of set auth if_infos failed.\n");
		ret = UGW_FAILED;
		goto OUT;
	}
OUT:
	if (ioc_obj) {
		free_ioc_obj(ioc_obj);
		ioc_obj = NULL;
	}
	return ret;
}


/*****************************************UPDATE_AUTH_OPTIONS*******************************/
static void display_auth_options_ioc_obj(struct auth_ioc_arg *ioc_obj)
{
	assert(ioc_obj);
	struct ioc_auth_options *option = 
			(struct ioc_auth_options*)((void*)ioc_obj + sizeof(struct auth_ioc_arg));
	AUTH_DEBUG("*************AUTH_OPTION IOC_OBJ***************\n");
	AUTH_DEBUG("IOC_TYPE:%d\n", ioc_obj->type);
	AUTH_DEBUG("IOC_NUM:%d\n", ioc_obj->num);
	AUTH_DEBUG("DATA_LEN:%d\n", ioc_obj->data_len);
	AUTH_DEBUG("USER_CHECK_INTVAL:%u\n", option->user_check_intval);
	AUTH_DEBUG("REDIRECT_URL:%s\n", option->redirect_url);
	AUTH_DEBUG("REDIRECT_TITLE:%s\n", option->redirect_title);
	AUTH_DEBUG("BYPASS_ENABLE:%u\n", option->bypass_enable);
	AUTH_DEBUG("***********************************************\n\n");
}

static int auth_options_valid_check(uint32_t intval, const char *url, const char *title)
{
	return UGW_SUCCESS;
}


int set_auth_options(struct auth_ioc_arg *arg, uint32_t intval, const char *url, const char *title, uint32_t bypass)
{
	assert(arg);
	struct ioc_auth_options *option = NULL;

	if (auth_options_valid_check(intval, url, title) == UGW_FAILED) {
		return UGW_FAILED;
	} 
	option = (struct ioc_auth_options*)((void*)arg + sizeof(struct auth_ioc_arg));
	option->user_check_intval = intval;
	safe_strncpy(option->redirect_url, url, REDIRECT_URL_MAX);
	safe_strncpy(option->redirect_title, title, REDIRECT_TITLE_MAX);
	option->bypass_enable = bypass;
	return UGW_SUCCESS;
}


int update_auth_options_to_kernel(struct auth_options *option)
{
	assert(option);
	int ret = UGW_SUCCESS;
	struct auth_ioc_arg *ioc_obj = create_ioc_obj(AUTH_OPTION, 1);
	if (ioc_obj == NULL) {
		AUTH_ERROR("No mem.\n");
		ret = UGW_FAILED;
		goto OUT;
	}
	if (set_auth_options(ioc_obj, option->user_check_intval, option->redirect_url, 
			option->redirect_title, option->bypass_enable) == UGW_FAILED) {
		ret =  UGW_FAILED;
		goto OUT;
	}
#if DEBUG_ENABLE
	display_auth_options_ioc_obj(ioc_obj);
#endif
	if (ioctl(s_dev_fd, SIOCSAUTHOPTIONS, ioc_obj) != 0) {
		AUTH_ERROR("ioctl of set auth options failed.\n");
		ret = UGW_FAILED;
		goto OUT;
	}
OUT:
	if (ioc_obj) {
		free_ioc_obj(ioc_obj);
		ioc_obj = NULL;
	}
	return ret;
}


/*****************************************UPDATE_USER_STATUS**********************************/
static void display_update_user_stat_ioc_obj(struct auth_ioc_arg *ioc_obj)
{
	assert(ioc_obj);
	int i = 0;
	struct user_info *users = 
			(struct user_info*)((void*)ioc_obj + sizeof(struct auth_ioc_arg));
	AUTH_DEBUG("*************UPDATE_USER IOC_OBJ***************\n");
	AUTH_DEBUG("IOC_TYPE:%d\n", ioc_obj->type);
	AUTH_DEBUG("IOC_NUM:%d\n", ioc_obj->num);
	AUTH_DEBUG("DATA_LEN:%d\n", ioc_obj->data_len);
	for (i = 0; i < ioc_obj->num; i++) {
		 AUTH_INFO("UserMac:%02X:%02X:%02X:%02X:%02X:%02X.\n", 
				users[i].mac[0],  users[i].mac[1],  users[i].mac[2],
				users[i].mac[3],  users[i].mac[4],  users[i].mac[5]);
		AUTH_INFO("Action: %d.\n", users[i].status);
	}
	AUTH_DEBUG("***********************************************\n\n");
}


static int user_set_stat_valid_check(uint32_t status, const unsigned char *mac)
{
	return UGW_SUCCESS;
}


int set_user_set_stat(struct auth_ioc_arg *arg, uint16_t obj_id, uint32_t status, const unsigned char *mac)
{
	assert(arg);
	struct user_info *user = NULL;

	if (user_set_stat_valid_check(status, mac) == UGW_FAILED) {
		return UGW_FAILED;
	}
	if (obj_id >= arg->num) {
		AUTH_ERROR("OBJ_ID(%u) >= OBJ_COUNT(%u) out of range.\n");
		return UGW_FAILED;
	}
	user = (struct user_info*)((void*)arg + sizeof(struct auth_ioc_arg));
	user[obj_id].status = status;
	memcpy(user[obj_id].mac, mac, ETH_ALEN);
	return UGW_SUCCESS;
}


int update_user_stat_to_kernel(struct user_info *users, uint16_t nc_user)
{
	assert(users);
	int i = 0, ret = UGW_SUCCESS;
	struct auth_ioc_arg *ioc_obj = NULL;
	if (nc_user == 0) {
		AUTH_ERROR("Input parameters invalid.\n");
		ret = UGW_FAILED;
		goto OUT;
	}

	ioc_obj = create_ioc_obj(USER_SSTAT, nc_user);
	if (ioc_obj == NULL) {
		AUTH_ERROR("No mem.\n");
		ret = UGW_FAILED;
		goto OUT;
	}
	for (i = 0; i < nc_user; i++) {
		if (set_user_set_stat(ioc_obj, i, users[i].status, users[i].mac) == UGW_FAILED) {
			ret = UGW_FAILED;
			break;
		}
	}
#if DEBUG_ENABLE
	display_update_user_stat_ioc_obj(ioc_obj);
#endif
	if (ioctl(s_dev_fd, SIOCSUSRSTAT, ioc_obj) != 0) {
		AUTH_ERROR("ioctl of set user status failed.\n");
	}
OUT:
	if (ioc_obj) {
		free_ioc_obj(ioc_obj);
		ioc_obj = NULL;
	}
	return ret;
}


/*************************************GET_USER_INFO*******************************************/
static int user_get_stat_valid_check(uint16_t nc_element, uint64_t tm_stamp, unsigned long addr)
{
	return UGW_SUCCESS;
}


int set_user_get_stat(struct auth_ioc_arg *arg, uint16_t nc_element, uint64_t tm_stamp, unsigned long addr)
{	
	assert(arg);
	struct user_stat_assist *assist = NULL;
	if (user_get_stat_valid_check(nc_element, tm_stamp, addr) == UGW_FAILED) {
		return UGW_FAILED;
	}
	assist = (struct user_stat_assist*)((void*)arg + sizeof(struct auth_ioc_arg));
	assist->nc_element = nc_element;
	assist->tm_stamp = tm_stamp;
	assist->addr = addr;
	return UGW_SUCCESS;
}


static struct user_stat_assist *create_user_info_buffer(uint16_t size)
{
	struct user_stat_assist *assist = NULL;
	uint32_t header_len = 0, body_len = 0;

	if (size == 0) {
		AUTH_ERROR("Input parameters [%u] invalid.\n", size);
		return NULL;
	}
	header_len = sizeof(struct user_stat_assist);
	body_len = size * sizeof(struct user_info);
	assist = (struct user_stat_assist*)malloc(header_len + body_len);
	if (assist == NULL) {
		AUTH_ERROR("No mem.\n");
		return NULL;
	}
	memset(assist, 0, (header_len + body_len));
}


static void free_user_info_buffer(struct user_stat_assist *assist)
{
	if (assist == NULL) {
		return;
	}
	free(assist);
}


static void print_user_info(struct user_stat_assist *assist, struct user_info *users)
{
	assert(assist);
	assert(users);
	int i = 0;
	uint32_t user_ip = 0;
	for (i = 0; i < assist->nc_user; i++) {
		printf("ip:"IPQUAD_FMT" st:%u jf:%llu mac:%02x:%02x:%02x:%02x:%02x:%02x type:%u\n", 
				HIPQUAD(users[i].ipv4), users[i].status, users[i].jf,
				users[i].mac[0], users[i].mac[1], users[i].mac[2],
				users[i].mac[3], users[i].mac[4], users[i].mac[5], 
				users[i].auth_type);
	}
}


int get_all_user_info_from_kernel()
{
	int more = 1, ret = 0, buff_len = 0;
	uint64_t tm_stamp = clock();
	struct user_stat_assist *assist = NULL;
	struct auth_ioc_arg *ioc_obj = NULL;

	ioc_obj = create_ioc_obj(USER_GSTAT, 1);
	if (ioc_obj == NULL) {
		ret = UGW_FAILED;
		goto OUT;
	}
	
	assist = create_user_info_buffer(AUTH_USER_REQ_SIZE);
	buff_len = sizeof(struct user_stat_assist) + AUTH_USER_REQ_SIZE * sizeof(struct user_info);
	if (assist == NULL) {
		ret = UGW_FAILED;
		goto OUT;
	}

	while (more) {
		if (set_user_get_stat(ioc_obj, AUTH_USER_REQ_SIZE, tm_stamp, (unsigned long)assist) == UGW_FAILED) {
			ret = UGW_FAILED;
			break;
		}
		if (ioctl(s_dev_fd, SIOCGUSRSTAT, ioc_obj) != 0) {
			AUTH_ERROR("ioctl of getting user info failed.\n");
			ret = UGW_FAILED;
			break;
		}
		print_user_info(assist, (struct user_info*)((void*)assist + sizeof(struct user_stat_assist)));
		more = assist->more;
		memset(assist, 0, buff_len);
	}
OUT:
	if (ioc_obj) {
		free_ioc_obj(ioc_obj);
		ioc_obj = NULL;
	}
	if (assist) {
		free_user_info_buffer(assist);
		assist = NULL;
	}
	return ret;
}


/*
*Notice, All number data between user space and kernel are host order.
*/
static int auth_config_to_kernel(struct auth_global_config *config)
{
	int i;
	if (config->update_auth_opt) {
		update_auth_options_to_kernel(&config->auth_opt);
	}

	if (config->update_ip_rules) {
		update_auth_ip_rules_to_kernel(config->ip_rules, config->nc_ip_rule);
	}

	if (config->update_if_infos) {
		update_auth_if_infos_to_kernel(config->if_infos, config->nc_if);
	}

	if (config->update_url_infos) {
		update_auth_url_infos_to_kernel(config->url_infos, config->nc_url);
	}

	if (config->update_user) {
		update_user_stat_to_kernel(config->users, config->nc_user);
	}

	if (config->get_all_user) {
		AUTH_INFO("GetAllUser:%d.\n", config->get_all_user);
		get_all_user_info_from_kernel();
	}
}


static int dev_open()
{
	if (s_dev_fd >= 0) {
		return UGW_SUCCESS;
	}
	s_dev_fd = open(AUTH_USER_INFO_DEV, O_RDWR);
	if (s_dev_fd < 0) {
		AUTH_ERROR("Open /dev/auth_user_info failed.\n");
		return UGW_FAILED;
	}
	return UGW_SUCCESS;
}


static int dev_close()
{
	if (s_dev_fd >= 0) {
		if (close(s_dev_fd) == -1) {
			AUTH_ERROR("Close fd of /dev/auth_user_info failed for %s.\n", strerror(errno));	
			return UGW_FAILED;	
		}
	}
	return UGW_SUCCESS;
}


static void auth_redirect_usage(int status)
{
	int i;
  	FILE *f = status ? stderr : stdout;
  	AUTH_ERROR("%s\n", "Usage: auth_redirect json_str");
}


static int auth_input_valid_check(int argc, char **argv)
{
	if(argc < 2) {
    	auth_redirect_usage(1);
    	return UGW_FAILED;
	}
	if((argc == 2) && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
		auth_redirect_usage(0);
		return UGW_FAILED;
	}
	return UGW_SUCCESS;
}


int main(int argc, char **argv)
{
	int ret = 0;
	struct auth_global_config auth_config;	

	auth_config_clear(&auth_config);
	ret = auth_input_valid_check(argc, argv);
	if (ret == UGW_FAILED) {
		goto OUT;
	}

	ret = auth_config_parsing(&auth_config, argv[1], strlen(argv[1]));
	if (ret == UGW_FAILED) {
		goto OUT;
	}

	ret = dev_open();
	if (ret == UGW_FAILED) {
		goto OUT;
	}
	ret = auth_config_to_kernel(&auth_config);

OUT:
	auth_config_free(&auth_config);
	dev_close();
	return ret;
}






