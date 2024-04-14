#ifndef	_SRC_C_KDD_FEATURES_H_
#define	_SRC_C_KDD_FEATURES_H_

#include "suricata-common.h"
//#include <stdlib.h>
//#include <string.h>
//#include <stdio.h>

//typedef unsigned char uint8_t;
//typedef unsigned short int uint16_t;
//typedef unsigned int uint32_t;
//typedef signed long long int64_t;

#define MAX_KDD_FEATURES 43

typedef enum KDDProtocolType_{
  KDD_PROTOCOL_TCP = 0,
  KDD_PROTOCOL_UDP,
  KDD_PROTOCOL_ICMP,
  KDD_PROTOCOL_UNKNOW,
  KDD_PROTOCOL_MAX  
}KDDProtocolType;

typedef enum KDDServiceType_
{
  KDD_SERVICE_TCP_RJE = 0,
  KDD_SERVICE_TCP_ECHO,
  KDD_SERVICE_TCP_DISCARD,
  KDD_SERVICE_TCP_SYSTAT,
  KDD_SERVICE_TCP_DAYTIME,
  KDD_SERVICE_TCP_NETSTAT,
  KDD_SERVICE_TCP_FTP_DATA, 
  KDD_SERVICE_TCP_FTP,
  KDD_SERVICE_TCP_SSH,
  KDD_SERVICE_TCP_TELNET,
  KDD_SERVICE_TCP_SMTP,
  KDD_SERVICE_TCP_TIME,
  KDD_SERVICE_TCP_NAME,
  KDD_SERVICE_TCP_WHOIS,
  KDD_SERVICE_TCP_DOMAIN,
  KDD_SERVICE_TCP_GOPHER,
  KDD_SERVICE_TCP_FINGER,
  KDD_SERVICE_TCP_HTTP,
  KDD_SERVICE_TCP_CTF,
  KDD_SERVICE_TCP_SUPDUP,
  KDD_SERVICE_TCP_HOSTNAMES,
  KDD_SERVICE_TCP_CSNET_NS,
  KDD_SERVICE_TCP_POP_2,
  KDD_SERVICE_TCP_POP_3,
  KDD_SERVICE_TCP_SUNRPC,
  KDD_SERVICE_TCP_AUTH,
  KDD_SERVICE_TCP_UUCP_PATH,
  KDD_SERVICE_TCP_NNTP,
  KDD_SERVICE_TCP_NETBIOS_NS,
  KDD_SERVICE_TCP_NETBIOS_DGM,
  KDD_SERVICE_TCP_NETBIOS_SSN,
  KDD_SERVICE_TCP_SQL_NET,
  KDD_SERVICE_TCP_VMNET,
  KDD_SERVICE_TCP_BGP,
  KDD_SERVICE_TCP_IRC,
  KDD_SERVICE_TCP_Z39_50,
  KDD_SERVICE_TCP_LINK, 
  KDD_SERVICE_TCP_LDAP,
  KDD_SERVICE_TCP_NNSP,
  KDD_SERVICE_TCP_HTTP_443,
  KDD_SERVICE_TCP_EXEC,
  KDD_SERVICE_TCP_LOGIN,
  KDD_SERVICE_TCP_SHELL,
  KDD_SERVICE_TCP_PRINTER,
  KDD_SERVICE_TCP_EFS,
  KDD_SERVICE_TCP_COURIER,
  KDD_SERVICE_TCP_UUCP,
  KDD_SERVICE_TCP_KLOGIN,
  KDD_SERVICE_TCP_KSHELL,
  KDD_SERVICE_TCP_IMAP4,
  KDD_SERVICE_TCP_MTP,
  KDD_SERVICE_TCP_HTTP_2784, 
  KDD_SERVICE_TCP_AOL,
  KDD_SERVICE_TCP_X11,
  KDD_SERVICE_TCP_HTTP_8001,  
//  case 22: return KDD_SERVICE_TCP_HARVEST;
//  case 22: return KDD_SERVICE_TCP_REMOTE_JOB;    
//  case 22: return KDD_SERVICE_TCP_PM_DUMP;
  KDD_SERVICE_TCP_WELKNOW,   //    1 -> 1024
  KDD_SERVICE_TCP_OTHER,    // 1025 -> 49151
  KDD_SERVICE_TCP_PRIVATE,  //49152 ->
  KDD_SERVICE_ICMP_ECO_I,
  KDD_SERVICE_ICMP_ECR_I,
  KDD_SERVICE_ICMP_URP_I,
  KDD_SERVICE_ICMP_TIM_I,
  KDD_SERVICE_UNKNOWN,
  KDD_SERVICE_TCP_MAX
}KDDServiceType;

typedef enum KDDFlagType_
{
  KDD_FLAG_SF = 0,  //Normal establishment and termination
  KDD_FLAG_S0,      //Connection attempt seen, no reply
  KDD_FLAG_S1,      //Established, not terminated
  KDD_FLAG_S2,      //Established and close attempt by originator seen (but no reply from responder)
  KDD_FLAG_S3,      //Established and close attempt by responder seen (but no reply from originator)
  KDD_FLAG_REJ,     //Connection attempt rejected
  KDD_FLAG_RSTO,    //Connection reset by the originator
  KDD_FLAG_RSTR,    //Connection reset by the responder
  KDD_FLAG_RSTOS0,  //Originator sent a SYN followed by a RST, we never saw a SYN-ACK from the responder
  KDD_FLAG_SH,       //Originator sent a SYN followed by a FIN, we never saw a SYN-ACK from the responder
  KDD_FLAG_OTH,     //No SYN seen, just midstream traffic
  KDD_FLAG_MAX
}KDDFlagType;

typedef enum KDDLabelType_{
  KDD_LABEL_neptune = 1,
  KDD_LABEL_normal,
  KDD_LABEL_saint,
  KDD_LABEL_mscan,
  KDD_LABEL_guess_passwd,
  KDD_LABEL_smurf,
  KDD_LABEL_apache2,
  KDD_LABEL_satan,
  KDD_LABEL_buffer_overflow,
  KDD_LABEL_back,
  KDD_LABEL_warezmaster,
  KDD_LABEL_snmpgetattack,
  KDD_LABEL_processtable,
  KDD_LABEL_pod,
  KDD_LABEL_httptunnel,
  KDD_LABEL_nmap,
  KDD_LABEL_ps,
  KDD_LABEL_snmpguess,
  KDD_LABEL_ipsweep,
  KDD_LABEL_mailbomb,
  KDD_LABEL_portsweep,
  KDD_LABEL_multihop,
  KDD_LABEL_named,
  KDD_LABEL_sendmail,
  KDD_LABEL_loadmodule,
  KDD_LABEL_xterm,
  KDD_LABEL_worm,
  KDD_LABEL_teardrop,
  KDD_LABEL_rootkit,
  KDD_LABEL_xlock,
  KDD_LABEL_perl,
  KDD_LABEL_land,
  KDD_LABEL_xsnoop,
  KDD_LABEL_sqlattack,
  KDD_LABEL_ftp_write,
  KDD_LABEL_imap,
  KDD_LABEL_udpstorm,
  KDD_LABEL_phf,
  KDD_LABEL_UNKNOWN,
  KDD_LABEL_MAX
}KDDLabelType;

typedef struct KDDCheckFeatures_{
  //2second
  uint32_t totalConnection_2s;  
  uint32_t sameDstIP_2s;             //23 - one destination IP
  uint32_t sameDstIP_2s_FlagSx;      //25
  uint32_t sameDstIP_2s_FlagREJ;     //27
  uint32_t sameDstIP_2s_samePort;    //29
  uint32_t sameDstIP_2s_diffPort;    //30
  
  uint32_t sameDstPort_2s;           //24
  uint32_t sameDstPort_2s_FlagSx;    //26
  uint32_t sameDstPort_2s_FlagREJ;   //28
  uint32_t sameDstPort_2s_diffDstIP; //31
  
  /////
  uint32_t totalConnection;
  uint32_t sameSrcIP_DstIP_DstPort;
  uint32_t sameDstIP;             //32 - one destination IP
  uint32_t sameDstIP_samePort;    //34
  uint32_t sameDstIP_diffPort;    //35
  uint32_t sameDstIP_FlagREJ;     //38
  uint32_t sameDstIP_FlagSx;      //40

  uint32_t sameDstPort;           //33
  uint32_t sameDstPort_sameSrcIP; //36
  uint32_t sameDstPort_diffSrcIP; //37  
  uint32_t sameDstPort_FlagREJ;   //39
  uint32_t sameDstPort_FlagSx;    //41

}KDDCheckFeatures;

typedef struct KDD_Features_{
  uint32_t Duration;              //1
  uint8_t Protocol_Type;        //2
  uint16_t Service;             //3
  uint8_t Flag;                 //4
  uint32_t Src_Bytes;             //5
  uint32_t Dst_Bytes;             //6
  uint8_t Land;                 //7
  uint8_t Wrong_Fragment;       //8
  uint8_t Urgent;               //9
  uint8_t Hot;                  //10
  uint8_t Num_Failed_Logins;    //11
  uint8_t Logged_In;            //12
  uint16_t Num_Compromised;     //13
  uint8_t Root_Shell;           //14
  uint8_t Su_Attempted;         //15
  uint16_t Num_Root;            //16
  uint8_t Num_File_Creations;   //17
  uint8_t Num_Shells;           //18
  uint8_t Num_Access_Files;     //19
  uint8_t Num_Outbound_Cmds;    //20
  uint8_t Is_Hot_Logins;        //21
  uint8_t Is_Guest_Login;       //22
  uint16_t Count;               //23  -> 25,27,29,30
  uint16_t Srv_Count;           //24  -> 26,28,31
  float Serror_Rate;                  //25
  float Srv_Serror_Rate;              //26
  float Rerror_Rate;                  //27
  float Srv_Rerror_Rate;              //28
  float Same_Srv_Rate;                //29
  float Diff_Srv_Rate;                //30
  float Srv_Diff_Host_Rate;           //31
  uint16_t Dst_Host_Count;      //32  -> 34,35,38,40
  uint16_t Dst_Host_Srv_Count;  //33  -> 36,37,39,41
  float Dst_Host_Same_Srv_Rate;       //34
  float Dst_Host_Diff_Srv_Rate;       //35
  float Dst_Host_Same_Src_Port_Rate;  //36
  float Dst_Host_Srv_Diff_Host_Rate;  //37
  float Dst_Host_Serror_Rate;         //38
  float Dst_Host_Srv_Serror_Rate;     //39
  float Dst_Host_Rerror_Rate;         //40
  float Dst_Host_Srv_Rerror_Rate;     //41
  uint8_t Label;                //42
  uint8_t Score;                //43
}KDD_Features;

typedef struct KDDNode_{
  struct KDDNode_* next;
  KDD_Features* f;
}KDDNode;

typedef struct KDDLabelNode_{
  KDDNode* top;
  KDDNode* bot;
  uint32_t count;
}KDDLabelNode;

typedef struct KDDMatch_{
  struct KDDMatch_* next;
  KDDLabelNode* lblNode;
}KDDMatch;
typedef struct KDDMatchNode_{
  KDDMatch* top;
  KDDMatch* bot;
  uint32_t count;
}KDDMatchNode;

typedef struct KDDFlagNode_{
  KDDLabelNode labels[KDD_LABEL_MAX];
}KDDFlagNode;
typedef struct KDDServiceNode_{
  KDDFlagNode   flags[KDD_FLAG_MAX];
}KDDServiceNode;
typedef struct KDDProtocolNode_{
  KDDServiceNode   services[KDD_SERVICE_TCP_MAX];
}KDDProtocolNode;
typedef struct KDDRules_{
  KDDProtocolNode   protocols[KDD_PROTOCOL_MAX];
}KDDRules;

typedef struct KDDTracker_{
  struct KDDTracker_* next;
  struct KDDTracker_* prev;
  uint32_t hash;
}KDDTracker;
typedef struct KDDTrackerQueue_{
  KDDTracker *top;
  KDDTracker *bot;
  uint32_t len;
  SCMutex m;
}KDDTrackerQueue;

KDDProtocolType     KDDGetProtocol(char*);
KDDServiceType      KDDGetService(KDDProtocolType, char*);
KDDFlagType         KDDGetFlag(char*);
KDDLabelType        KDDGetLabel(char*);

const char*         KDDGetNameProtocol(KDDProtocolType);
const char*         KDDGetNameService(KDDServiceType);
const char*         KDDGetNameFlag(KDDFlagType);
const char*         KDDGetNameLabel(KDDLabelType);

KDDProtocolType     KDDGetProtocolType(uint8_t proto);
KDDServiceType      KDDGetServiceType(KDDProtocolType, uint16_t);

int64_t             KDDCreateKey(KDD_Features* f);

void                KDDInitRules(KDDRules* rule);
void                KDDAddRule(KDDRules* rule,KDD_Features* f);
void                KDDShowRule(KDDRules* rule);
int                 KDDShowRuleFilter(KDDRules* rule,KDDProtocolType,KDDServiceType,KDDFlagType,KDDLabelType);
void                KDDShowRuleFilter01(KDDRules* rule,KDDProtocolType,KDDServiceType,KDDFlagType);
void                KDDShowRuleFilter02(KDDRules* rule,KDDProtocolType,KDDServiceType,KDDLabelType);

void                KDDAddMatch(KDDMatchNode*, KDDLabelNode*);
void                KDDRemMatch(KDDMatchNode*);

void                KDDTrackerEnqueue(KDDTrackerQueue*, KDDTracker*);
int                 KDDTrackerRemove(KDDTrackerQueue*, KDDTracker*);
KDDTracker*         KDDTrackerDequeue (KDDTrackerQueue *);

#endif