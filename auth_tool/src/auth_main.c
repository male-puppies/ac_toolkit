#include "auth.h"


#define DRV_VERSION	"0.1.1"
#define DRV_DESC	"auth driver"


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
	*res = AUTH_NEW_N(char, len + 1);
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
static void auth_interface_cleanup(struct user_info *user)
{
	memset(user, 0, sizeof(struct user_info));
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

	if (auth_json_integer_map(&if_info->status, 
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
	auth_interface_cleanup(rule);
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

	if (auth_json_string_map(&if_info->name,
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


/***************************************ip_rule_parsing**************************************/
static int auth_ip_range_init(struct ip_range *ip_rule, const nx_json *js)
{
	int ret = -1;
	char *start_ip = NULL, *end_ip = NULL;

	memset(ip_rule, 0, sizeof(struct ip_range));
	if (auth_json_string_map(&start_ip, nx_json_get(js, "Start"), 
			"config.AuthPolicy[n].IpRange[n].Start", IPV4_STR_LEN_MAX) != 0)
	{
		goto fail;
	}

	if (auth_str_to_ip(start_ip, &ip_rule->min) != 0)
	{
		goto fail;
	}

	if (auth_json_string_map(&end_ip, nx_json_get(js, "End"), 
			"config.AuthPolicy[n].IpRange[n].End", IPV4_STR_LEN_MAX) != 0)
	{
		goto fail;
	}

	if (auth_str_to_ip(end_ip, &ip_rule->max) != 0)
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
	free(rule->ip_rules);
	rule->ip_rules = NULL;
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

	if (auth_json_integer_map(&rule->enable, 
		nx_json_get(js, "Enable"),  
		"config.AuthPolicy[n].Enable",
		0, 1) != 0)
	{
		goto fail;
	}

	if (auth_json_array_map(&rule->ip_rules, &rule->nc_ip_rule,
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
static int do_auth_option_parsing(struct auth_options_st *auth_option, const nx_json *js)
{
	memset(auth_option, 0, sizeof(struct auth_options_st));

	if (auth_json_integer_map(&auth_option->user_check_intval, 
		nx_json_get(js, "CheckOffline"),  
		"config.GlobaleAuthOption.CheckOffline",
		0, USR_CHECK_INTVAL_MAX) != 0)
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
	if (js_elem) {
		if (do_auth_option_parsing(&config->auth_opt, js_elem) == UGW_SUCCESS) {
			config->update_auth_opt = 1;
		}
		else {
			goto fail;
		}
	}

	/*parse auth rules*/
	js_elem = nx_json_get(js, "AuthPolicy");
	if (js_elem) {
		if (do_auth_ip_rule_parsing(&config->ip_rules, &config->nc_ip_rule, js_elem) == UGW_SUCCESS) {
			config->update_ip_rules = 1;
		}
		else {
			goto faiL;
		}
	}

	/*parse interface*/
	js_elem = nx_json_get(js, "InterfaceInfo");
	if (js_elem) {
		if (do_auth_interface_parsing(&config->if_infos, &config->nc_if, js_elem) == UGW_SUCCESS) {
			config->update_if_infos = 1;
		}
		else {
			goto faiL;
		}
	}

	/*parse user status*/
	js_elem = nx_json_get(js, "UpdateUserStatus");
	if (js_elem) {
		if (do_auth_update_user_parsing(&config->users, &config->nc_user, js_elem) == UGW_SUCCESS) {
			config->update_user = 1;
		}
		else {
			goto faiL;
		}
	}

	/*get_all_user info*/
	js_elem =  nx_json_get(js, "GetAllUser");
	if (js_elem) {
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


static void auth_rule_dump(struct auth_ip_rule *rule)
{
	int i;

	AUTH_INFO("~~~~~~~~~ AUTH RULE [%s] ~~~~~~~~~\n", rule->name);
	AUTH_INFO("id: %u.\n", rule->id);
	AUTH_INFO("desc: %s.\n", rule->desc);
	AUTH_INFO("type: %u.\n", rule->type);
	AUTH_INFO("enable: %u.\n", rule->enable);
	AUTH_INFO("ip rules count: %u.\n", rule->nr_ip_rule);
	for (i = 0; i < rule->nr_ip_rule; i++)
	{
		struct ip_range *ip_rule = &rule->ip_rules[i];
		AUTH_INFO("ip rule %d: [%pI4h, %pI4h].\n", i, &ip_rule->min, &ip_rule->max);
	}
}


static void auth_option_dump(struct auth_options_st *option)
{
	int i;

	AUTH_INFO("~~~~~~~~~ AUTH OPTION~~~~~~~~~\n");
	AUTH_INFO("usr_check_intval: %u.\n", option->usr_check_intval);
	AUTH_INFO("redirect_url: %s.\n", option->redirect_url);
	AUTH_INFO("redirect_title: %s.\n", option->redirect_title);
	AUTH_INFO("whilte_ip_rules count:%u.\n", option->nr_ip_rule);
	for (i = 0; i < option->nr_ip_rule; i++)
	{
		struct ip_range *ip_rule = &option->white_ip_rules[i];
		AUTH_INFO("ip rule %d: [%pI4h, %pI4h].\n", i, &ip_rule->min, &ip_rule->max);
	}
}


static void auth_config_dump(struct auth_global_config *config)
{
	int i;

	AUTH_INFO("--------------- AUTH CONFIG ---------------\n");
	AUTH_INFO("auth rules count: %u.\n", config->nr_rule);
	for (i = 0; i < config->nr_rule; i++) 
	{
		auth_rule_dump(&config->rules[i]);
	}
	auth_option_dump(&config->auth_opt);
	AUTH_INFO("------------------------------------------\n");
}


/*parse config:Firstly, checking valid of config, and then parsing config, dumpping config lastly.*/
static int auth_config_parsing(struct auth_global_config *config, const char *json, size_t size)
{
	int ret = -1;
	char *json_data = NULL;
	const nx_json *js = NULL;

	memset(config, 0, sizeof(struct auth_global_config));
	json_data = AUTH_NEW_N(char, size + 1);
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

	auth_config_dump(config);
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
	if (auth_config == NULL) {
		return;
	}
	if (auth_config->ip_rules) {
		free(auth_config->ip_rules);
		auth_config->ip_rules = NULL;
	}

	if (auth_config->if_infos) {
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


/**********************************commit_to_kernel************************/
static int auth_config_to_kernel(struct auth_global_config *auth_config)
{

}


static int dev_open()
{
	if (s_dev_fd >= 0) {
		return UGW_SUCCESS;
	}
	fd = open(AUTH_USER_INFO_DEV, O_RDWR);
	if (fd < 0) {
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
  	AUTH_ERROR("%s\n", "Usage: auth_redirect par_str");
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






