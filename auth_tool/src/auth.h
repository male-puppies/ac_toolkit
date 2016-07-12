#ifndef _AUTH_H_
#define _AUTH_H_

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
 #include <arpa/inet.h>
#include <assert.h>
#include <stdarg.h>
#include "nxjson.h"

#define DEBUG_ENABLE 		1		/*DEBUG PRINT SWITCH*/

#define UGW_SUCCESS			0
#define UGW_FAILED			-1

#define SIOCSAUTHRULES		0x100	/*set auth rules*/
#define SIOCSAUTHOPTIONS	0x101	/*set auth options*/
#define SIOCSUSRSTAT		0x102	/*set usr status*/
#define SIOCGUSRSTAT		0x103	/*get usr status*/
#define SIOCSIFINFO			0x104	/*set network interface*/
#define SIOCSAUTHURLS       0X105   /*set bypass url*/
#define SIOCSDEBUGOPTIONS	0x106	/*set debug options*/
#define SIOCSAUTHHOSTS 		0x107 	/*set bypass host*/
#define SIOCSAUTHMAC		0x108	/*set bypass mac*/

#define ETH_ALEN				6

#define USR_CHECK_INTVAL_MIN	1
#define USR_CHECK_INTVAL_MAX	INT_MAX

#define	REDIRECT_URL_MAX		256
#define REDIRECT_TITLE_MAX		128

#define AUTH_RULE_COUNT_MAX		128		/*the max size of rule record*/
#define AUTH_RULE_NAME_MAX		128		/*the max name size of rule*/
#define IP_RULE_TYPE_NUM		3
#define AUTH_RULE_ID_MAX		INT_MAX
#define AUTH_IP_RANGE_COUNT_MAX	64		/*ip range of per ip rule*/
#define IPV4_STR_LEN_MAX		16
#define AUTH_IP_RULE_MAX_PRIORITY 255

#define MAC_STR_SIZE			17	/*DEMO:(38:4D:11:22:33:44)*/	

#define AUTH_USER_COUNT_MAX 	65535

#define IF_NAME_MAX				32	
#define NET_IF_TYPE_NUM			3


#define AUTH_USER_REQ_SIZE 		512
struct ip_range
{	/*host order which may be big endian or small endian*/
	uint32_t min;
	uint32_t max;
};

/*auth rule struct*/
struct auth_ip_rule
{
	char		*name;
	uint32_t 	type;
	uint32_t	enable;
	uint32_t 	priority;
	uint32_t 	timeout;
	struct ip_range *ip_ranges;
	uint32_t 	nc_ip_range;
	uint8_t 	step;
};

struct ioc_auth_ip_rule {
	char		name[AUTH_RULE_NAME_MAX];
	uint32_t 	type;
	uint32_t	enable;
	uint32_t 	priority;
	uint32_t 	timeout;
	uint8_t 	step;
	uint32_t 	nc_ip_range;
	/*struct ip_range *ip_ranges*/
};

/*interface info*/
struct auth_if_info {
	uint32_t type;
	char	*if_name;
};

/*url info*/
struct auth_url_info {
	uint32_t action;
	char	*uri;
	char 	*host;
	uint8_t step;
};

/*global white/black list*/
struct auth_host_info {
	char 	*host;
};

/*global auth options*/
struct auth_options
{
	uint32_t	user_check_intval;	/*unit:minutes*/
	char 		*redirect_url;
	char		*redirect_title;
	uint32_t    bypass_enable;
};
#pragma pack(4)
struct mac_info {
	uint32_t status;
	unsigned char mac[ETH_ALEN];
};

#pragma pack()

#pragma pack(4)
struct user_info {
	uint32_t ipv4;
	uint32_t status;
	unsigned long jf;
	unsigned char mac[ETH_ALEN];
	uint16_t auth_type;
	//unsigned char reserved[2];
};
#pragma pack()

/*global config*/
struct auth_global_config {
	struct auth_options auth_opt;
	uint8_t update_auth_opt;

	struct auth_ip_rule *ip_rules;
	uint32_t nc_ip_rule;
	uint8_t	update_ip_rules;

	struct auth_if_info *if_infos;
	uint32_t	nc_if;
	uint8_t update_if_infos;

	struct auth_url_info *url_infos;
	uint32_t 	nc_url;
	uint8_t update_url_infos;

	struct user_info *users;
	uint32_t nc_user;
	uint8_t update_user;
	
	struct mac_info *host_mac;
	uint32_t nc_mac;
	uint8_t update_host_mac;
	
	struct auth_host_info *host_infos;
	uint32_t nc_host;
	uint8_t update_host_infos;

	uint8_t get_all_user;
};

#define IPQUAD_FMT "%u.%u.%u.%u"
#define NIPQUAD(addr) \
 ((unsigned char *)&addr)[0], \
 ((unsigned char *)&addr)[1], \
 ((unsigned char *)&addr)[2], \
 ((unsigned char *)&addr)[3]

#define HIPQUAD(addr) \
 ((unsigned char *)&addr)[3], \
 ((unsigned char *)&addr)[2], \
 ((unsigned char *)&addr)[1], \
 ((unsigned char *)&addr)[0]


#define AUTH_NEW(type) \
	AUTH_NEW_N(1, type)

#define AUTH_NEW_N(n, type) \
	((type *)calloc((n), sizeof(type)))

#define AUTH_DEBUG(format,...)   do { fprintf(stderr, "%s "format, __func__, ##__VA_ARGS__); } while(0)
#define AUTH_INFO(format,...)    do { fprintf(stdout, "%s "format, __func__, ##__VA_ARGS__); } while(0)
#define AUTH_ERROR(format,...)    do { fprintf(stderr, "%s "format, __func__, ##__VA_ARGS__); } while(0)


//#define IP_RULE_TYPE_NUM	3
#define IP_RULE_TYPE_STR_LEN 8
enum IP_RULE_TYPE_E {
	NORMAL	= 0,
	WHITE	= 1,
	BLACK	= 2,
};

// /*ipv4 range*/
// struct auth_ip_rule {
// 	uint8_t 	type;	/*normal, white, black*/
// 	uint8_t		priority;
// 	uint8_t 	enable;
// 	uint32_t	min;	/*min ip*/
// 	uint32_t 	max;	/*max ip*/
// };
#pragma pack(4)
/*auth options*/
struct ioc_auth_options {
	uint32_t	user_check_intval;	/*unit: seconds*/
	char 		redirect_url[REDIRECT_URL_MAX];	
	char		redirect_title[REDIRECT_TITLE_MAX];
	uint32_t    bypass_enable;
};

enum ARG_TYPE_E {
	AUTH_RULE	= 0,
	AUTH_OPTION	= 1,
	USER_GSTAT	= 2,
	USER_SSTAT	= 3,
	NET_IF_INFO	= 4,
	BYPASS_URL_INFO = 5,
	BYPASS_HOST_INFO = 6,
	BYPASS_HOST_MAC = 7,
	/*add new type here*/
	INVALID_ARG_TYPE,
};
#define ARG_TYPE_NUM  (INVALID_ARG_TYPE + 1)
#define ARG_TYPE_STR_LEN 16


enum USER_STATUS {
	USER_OFFLINE = 0,
	USER_ONLINE = 1,
	/*new status add here*/
	INVALID_USER_STATUS,
};
#define USER_STATUS_NUM (INVALID_USER_STATUS + 1)
#define USER_STATUS_STR_LEN 16

// struct user_info {
// 	uint32_t ipv4;
// 	uint32_t status;
// 	uint64_t jf;
// 	unsigned char mac[ETH_ALEN];
// };

struct user_stat_assist {
	uint16_t more;		/*more user stat info*/
	uint16_t nc_element;/*num count of mem space which unit is sizeof(user_info)*/
	uint16_t nc_user;	/*real num of user*/
	uint16_t nc_unused; /*more user need to get*/
	unsigned long tm_stamp;
	unsigned long addr; /*user_space addr*/
};
/*"assit + user_info" kernel copy to user*/

#define NET_IF_TYPE_NUM	3
#define NET_IF_TYPE_STR_LEN 8
enum IF_TYPE_E {
	LAN_E	= 0,
	WAN_E	= 1,
	LOOP_E 	= 2,
};

/*interface info*/
struct ioc_auth_if_info {
	uint8_t 		type;
	unsigned char 	if_name[IF_NAME_MAX];
};


/*url info*/
#define BYPASS_URI_LEN 	64
#define BYPASS_HOST_LEN 64
struct ioc_auth_url_info {
	uint8_t 		action;
	uint8_t 		uri_len;
	uint8_t 		host_len;
	unsigned char 	uri[BYPASS_URI_LEN];
	unsigned char 	host[BYPASS_HOST_LEN];
	uint8_t			step;
};

struct ioc_auth_host_info {
	uint8_t 		host_len;
	unsigned char 	host[BYPASS_HOST_LEN];
};

/*ioctl cmd args*/
struct auth_ioc_arg {
	uint8_t		type;		/*element type, just for check*/
	uint16_t 	num;		/*element count*/
	uint16_t	data_len;	/*num * sizeof element*/
	/*element data body*/
};


// struct ioc_auth_ip_rule {
// 	char		name[AUTH_RULE_NAME_MAX];
// 	uint32_t 	type;
// 	uint32_t	enable;
// 	uint32_t 	priority;
// 	uint32_t 	nc_ip_range;
// 	/*struct ip_range *ip_ranges*/
// };
#pragma pack()
#endif
