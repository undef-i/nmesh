#ifndef NM_NL_H
#define NM_NL_H

#define NM_NL_FAM "nmesh"
#define NM_NL_VER 1

enum nm_cmd {
	NM_C_UNSPEC,
	NM_C_IF_NEW,
	NM_C_P_ADD,
	NM_C_R_FLUSH,
	NM_C_R_SET,
	NM_C_K_SET,
	NM_C_IF_DEL,
	__NM_C_MAX
};

#define NM_C_MAX (__NM_C_MAX - 1)

enum nm_attr {
	NM_A_UNSPEC,
	NM_A_IF_IDX,
	NM_A_P_ID,
	NM_A_V6_IP,
	NM_A_EP_IP,
	NM_A_EP_PORT,
	NM_A_K_DIR,
	NM_A_K_DAT,
	NM_A_UDP_FD,
	__NM_A_MAX
};

#define NM_A_MAX (__NM_A_MAX - 1)

#endif
