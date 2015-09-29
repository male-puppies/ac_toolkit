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
#include "nxjson.h"


#define UGW_SUCCESS		0
#define UGW_FAILED		-1

#define SIOCSAUTHRULES		0x100	/*set auth rules*/
#define SIOCSAUTHOPTIONS	0x101	/*set auth options*/
#define SIOCSUSRSTAT		0x102	/*set usr status*/
#define SIOCGUSRSTAT		0x103	/*get usr status*/
#define SIOCSIFINFO			0x104	/*set network interface*/

#define ETH_ALEN				6
#define	REDIRECT_URL_MAX		256
#define REDIRECT_TITLE_MAX		256
#define USR_CHECK_INTVAL_MAX	INT_MAX

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
{
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
	struct ip_range *ip_ranges;
	uint32_t 	nc_ip_range;
};


struct ioc_auth_ip_rule {
	char		name[AUTH_RULE_NAME_MAX];
	uint32_t 	type;
	uint32_t	enable;
	uint32_t 	priority;
	uint32_t 	nc_ip_range;
	/*struct ip_range *ip_ranges*/
};

// /*ipv4 range*/
// struct auth_ip_rule {
// 	uint8_t 	type;	/*normal, white, black*/
// 	uint8_t		priority;
// 	uint8_t 	enable;
// 	uint32_t	min;	/*min ip*/
// 	uint32_t 	max;	/*max ip*/
// };


/*interface info*/
struct auth_if_info {
	uint32_t type;
	char	*if_name;
};

/*global auth options*/
struct auth_options
{
	uint32_t	user_check_intval;	/*unit:minutes*/
	char 		*redirect_url;
	char		*redirect_title;
};

struct user_info {
	uint32_t ipv4;
	uint32_t status;
	uint64_t jf;
	unsigned char mac[ETH_ALEN];
};

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

	struct user_info *users;
	uint32_t nc_user;
	uint8_t update_user;

	uint8_t get_all_user;
};

#define NIPQUAD_FMT "%u.%u.%u.%u"
#define NIPQUAD(addr) \
 ((unsigned char *)&addr)[0], \
 ((unsigned char *)&addr)[1], \
 ((unsigned char *)&addr)[2], \
 ((unsigned char *)&addr)[3]


#define AUTH_NEW(type) \
	AUTH_NEW_N(1, type)

#define AUTH_NEW_N(n, type) \
	((type *)calloc((n), sizeof(type)))

#define AUTH_DEBUG(format,...)   do { fprintf(stdout, "%s "format, __func__, ##__VA_ARGS__); } while(0)
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

/*auth options*/
struct ioc_auth_options {
	uint32_t	user_check_intval;	/*unit: seconds*/
	char 		redirect_url[REDIRECT_URL_MAX];	
	char		redirect_title[REDIRECT_TITLE_MAX];
};

enum ARG_TYPE_E {
	AUTH_RULE	= 0,
	AUTH_OPTION	= 1,
	USER_GSTAT	= 2,
	USER_SSTAT	= 3,
	NET_IF_INFO	= 4,
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
	uint64_t tm_stamp;
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

/*ioctl cmd args*/
struct auth_ioc_arg {
	uint8_t		type;		/*element type, just for check*/
	uint16_t 	num;		/*element count*/
	uint16_t	data_len;	/*num * sizeof element*/
	/*element data body*/
};

#endif