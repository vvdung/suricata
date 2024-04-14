#include "suricata-common.h"
#include "source-kdd-features.h"
#include "flow-queue.h"

KDDProtocolType KDDGetProtocol(char* s){
  if (strcmp(s,"tcp") == 0) return KDD_PROTOCOL_TCP;
  if (strcmp(s,"udp") == 0) return KDD_PROTOCOL_UDP;
  if (strcmp(s,"icmp") == 0) return KDD_PROTOCOL_ICMP;
  return KDD_PROTOCOL_UNKNOW;
}
const char* KDDGetNameProtocol(KDDProtocolType t){
  switch (t){
    case KDD_PROTOCOL_TCP: return "tcp";
    case KDD_PROTOCOL_UDP: return "udp";
    case KDD_PROTOCOL_ICMP: return "icmp";
    default: return "unknow";
  }  
}
KDDProtocolType KDDGetProtocolType(uint8_t proto){
  switch (proto){
    case IPPROTO_TCP: return KDD_PROTOCOL_TCP;
    case IPPROTO_UDP: return KDD_PROTOCOL_UDP;
    case IPPROTO_ICMP: return KDD_PROTOCOL_ICMP;
    default: return KDD_PROTOCOL_UNKNOW;
  }
  
}
KDDServiceType  KDDGetService(KDDProtocolType protoType, char*s){
  switch (protoType){
    case KDD_PROTOCOL_TCP:
    case KDD_PROTOCOL_UDP:
      if (strcmp(s,"private") == 0) return KDD_SERVICE_TCP_PRIVATE;
      if (strcmp(s,"ftp_data") == 0) return KDD_SERVICE_TCP_FTP_DATA;
      if (strcmp(s,"telnet") == 0) return KDD_SERVICE_TCP_TELNET;
      if (strcmp(s,"http") == 0) return KDD_SERVICE_TCP_HTTP;
      if (strcmp(s,"smtp") == 0) return KDD_SERVICE_TCP_SMTP;
      if (strcmp(s,"ftp") == 0) return KDD_SERVICE_TCP_FTP;
      if (strcmp(s,"ldap") == 0) return KDD_SERVICE_TCP_LDAP;
      if (strcmp(s,"pop_3") == 0) return KDD_SERVICE_TCP_POP_3;
      if (strcmp(s,"courier") == 0) return KDD_SERVICE_TCP_COURIER;
      if (strcmp(s,"discard") == 0) return KDD_SERVICE_TCP_DISCARD;
      if (strcmp(s,"imap4") == 0) return KDD_SERVICE_TCP_IMAP4;
      if (strcmp(s,"systat") == 0) return KDD_SERVICE_TCP_SYSTAT;
      if (strcmp(s,"iso_tsap") == 0) return KDD_SERVICE_TCP_PRIVATE;
      if (strcmp(s,"other") == 0) return KDD_SERVICE_TCP_OTHER;
      if (strcmp(s,"csnet_ns") == 0) return KDD_SERVICE_TCP_CSNET_NS;
      if (strcmp(s,"finger") == 0) return KDD_SERVICE_TCP_FINGER;
      if (strcmp(s,"uucp") == 0) return KDD_SERVICE_TCP_UUCP;
      if (strcmp(s,"whois") == 0) return KDD_SERVICE_TCP_WHOIS;
      if (strcmp(s,"netbios_ns") == 0) return KDD_SERVICE_TCP_NETBIOS_NS;
      if (strcmp(s,"link") == 0) return KDD_SERVICE_TCP_LINK;
      if (strcmp(s,"Z39_50") == 0) return KDD_SERVICE_TCP_Z39_50;
      if (strcmp(s,"sunrpc") == 0) return KDD_SERVICE_TCP_SUNRPC;
      if (strcmp(s,"auth") == 0) return KDD_SERVICE_TCP_AUTH;
      if (strcmp(s,"netbios_dgm") == 0) return KDD_SERVICE_TCP_NETBIOS_DGM;
      if (strcmp(s,"uucp_path") == 0) return KDD_SERVICE_TCP_UUCP_PATH;
      if (strcmp(s,"vmnet") == 0) return KDD_SERVICE_TCP_VMNET;
      if (strcmp(s,"domain") == 0) return KDD_SERVICE_TCP_DOMAIN;
      if (strcmp(s,"name") == 0) return KDD_SERVICE_TCP_NAME;
      if (strcmp(s,"pop_2") == 0) return KDD_SERVICE_TCP_POP_2;
      if (strcmp(s,"http_443") == 0) return KDD_SERVICE_TCP_HTTP_443;
      if (strcmp(s,"login") == 0) return KDD_SERVICE_TCP_LOGIN;
      if (strcmp(s,"gopher") == 0) return KDD_SERVICE_TCP_GOPHER;
      if (strcmp(s,"exec") == 0) return KDD_SERVICE_TCP_EXEC;
      if (strcmp(s,"time") == 0) return KDD_SERVICE_TCP_TIME;
      if (strcmp(s,"remote_job") == 0) return KDD_SERVICE_TCP_PRIVATE;
      if (strcmp(s,"ssh") == 0) return KDD_SERVICE_TCP_SSH;
      if (strcmp(s,"kshell") == 0) return KDD_SERVICE_TCP_KSHELL;
      if (strcmp(s,"sql_net") == 0) return KDD_SERVICE_TCP_SQL_NET;
      if (strcmp(s,"hostnames") == 0) return KDD_SERVICE_TCP_HOSTNAMES;
      if (strcmp(s,"echo") == 0) return KDD_SERVICE_TCP_ECHO;
      if (strcmp(s,"daytime") == 0) return KDD_SERVICE_TCP_DAYTIME;
      if (strcmp(s,"pm_dump") == 0) return KDD_SERVICE_TCP_PRIVATE;
      if (strcmp(s,"IRC") == 0) return KDD_SERVICE_TCP_IRC;
      if (strcmp(s,"netstat") == 0) return KDD_SERVICE_TCP_NETSTAT;
      if (strcmp(s,"ctf") == 0) return KDD_SERVICE_TCP_CTF;
      if (strcmp(s,"nntp") == 0) return KDD_SERVICE_TCP_NNTP;
      if (strcmp(s,"netbios_ssn") == 0) return KDD_SERVICE_TCP_NETBIOS_SSN;
      if (strcmp(s,"supdup") == 0) return KDD_SERVICE_TCP_SUPDUP;
      if (strcmp(s,"bgp") == 0) return KDD_SERVICE_TCP_BGP;
      if (strcmp(s,"nnsp") == 0) return KDD_SERVICE_TCP_NNSP;
      if (strcmp(s,"rje") == 0) return KDD_SERVICE_TCP_RJE;
      if (strcmp(s,"printer") == 0) return KDD_SERVICE_TCP_PRINTER;
      if (strcmp(s,"efs") == 0) return KDD_SERVICE_TCP_EFS;
      if (strcmp(s,"X11") == 0) return KDD_SERVICE_TCP_X11;
      if (strcmp(s,"klogin") == 0) return KDD_SERVICE_TCP_KLOGIN;
    break;
    case KDD_PROTOCOL_ICMP:
      if (strcmp(s,"eco_i") == 0) return KDD_SERVICE_ICMP_ECO_I;
      if (strcmp(s,"ecr_i") == 0) return KDD_SERVICE_ICMP_ECR_I;
      if (strcmp(s,"urp_i") == 0) return KDD_SERVICE_ICMP_URP_I;
      if (strcmp(s,"tim_i") == 0) return KDD_SERVICE_ICMP_TIM_I;
    break;
    default:
    return KDD_SERVICE_UNKNOWN;
  }
  return KDD_SERVICE_UNKNOWN;
}
KDDServiceType  KDDGetServiceType(KDDProtocolType t, uint16_t port){
  switch (t)
  {
  case KDD_PROTOCOL_TCP:
  case KDD_PROTOCOL_UDP: {
    switch (port) {
      case 5: return KDD_SERVICE_TCP_RJE;
      case 7: return KDD_SERVICE_TCP_ECHO;
      case 9: return KDD_SERVICE_TCP_DISCARD;
      case 11: return KDD_SERVICE_TCP_SYSTAT;
      case 13: return KDD_SERVICE_TCP_DAYTIME;
      case 15: return KDD_SERVICE_TCP_NETSTAT;
      case 20: return KDD_SERVICE_TCP_FTP_DATA; 
      case 21: return KDD_SERVICE_TCP_FTP;
      case 22: return KDD_SERVICE_TCP_SSH;
      case 23: return KDD_SERVICE_TCP_TELNET;
      case 25: return KDD_SERVICE_TCP_SMTP;
      case 37: return KDD_SERVICE_TCP_TIME;
      case 42: return KDD_SERVICE_TCP_NAME;
      case 43: return KDD_SERVICE_TCP_WHOIS;
      case 53: return KDD_SERVICE_TCP_DOMAIN;
      case 70: return KDD_SERVICE_TCP_GOPHER;
      case 79: return KDD_SERVICE_TCP_FINGER;
      case 80: return KDD_SERVICE_TCP_HTTP;  
      case 84: return KDD_SERVICE_TCP_CTF;
      case 95: return KDD_SERVICE_TCP_SUPDUP;
      case 101: return KDD_SERVICE_TCP_HOSTNAMES;
      case 105: return KDD_SERVICE_TCP_CSNET_NS;
      case 109: return KDD_SERVICE_TCP_POP_2;
      case 110: return KDD_SERVICE_TCP_POP_3;
      case 111: return KDD_SERVICE_TCP_SUNRPC;
      case 113: return KDD_SERVICE_TCP_AUTH;
      case 117: return KDD_SERVICE_TCP_UUCP_PATH;
      case 119: return KDD_SERVICE_TCP_NNTP;
      case 137: return KDD_SERVICE_TCP_NETBIOS_NS;
      case 138: return KDD_SERVICE_TCP_NETBIOS_DGM;
      case 139: return KDD_SERVICE_TCP_NETBIOS_SSN;
      case 150: return KDD_SERVICE_TCP_SQL_NET;
      case 175: return KDD_SERVICE_TCP_VMNET;
      case 179: return KDD_SERVICE_TCP_BGP;
      case 194: return KDD_SERVICE_TCP_IRC;
      case 210: return KDD_SERVICE_TCP_Z39_50;
      case 245: return KDD_SERVICE_TCP_LINK;   
      case 389: return KDD_SERVICE_TCP_LDAP;
      case 433: return KDD_SERVICE_TCP_NNSP;
      case 443: return KDD_SERVICE_TCP_HTTP_443;
      case 512: return KDD_SERVICE_TCP_EXEC;
      case 513: return KDD_SERVICE_TCP_LOGIN;
      case 514: return KDD_SERVICE_TCP_SHELL;
      case 515: return KDD_SERVICE_TCP_PRINTER;
      case 520: return KDD_SERVICE_TCP_EFS;
      case 530: return KDD_SERVICE_TCP_COURIER;
      case 540: return KDD_SERVICE_TCP_UUCP;
      case 543: return KDD_SERVICE_TCP_KLOGIN;
      case 544: return KDD_SERVICE_TCP_KSHELL;
      case 585: return KDD_SERVICE_TCP_IMAP4;
      case 1911: return KDD_SERVICE_TCP_MTP;
      case 2784: return KDD_SERVICE_TCP_HTTP_2784; 
      case 5190: return KDD_SERVICE_TCP_AOL;
      case 6000: return KDD_SERVICE_TCP_X11;
      case 8001: return KDD_SERVICE_TCP_HTTP_8001;  
    //  case 22: return KDD_SERVICE_TCP_HARVEST;
    //  case 22: return KDD_SERVICE_TCP_REMOTE_JOB;    
    //  case 22: return KDD_SERVICE_TCP_PM_DUMP;
    }
    if (port >= 49152) return KDD_SERVICE_TCP_PRIVATE;
    if (port > 1024) return KDD_SERVICE_TCP_OTHER;
    return KDD_SERVICE_TCP_WELKNOW;          
  }
  case KDD_PROTOCOL_ICMP:{
    uint8_t type = port >> 8;       /**< icmp type */
    //uint8_t code = port & 0x00FF;   /**< icmp code */
    switch (type){
      case 8: return KDD_SERVICE_ICMP_ECO_I;
      default: return KDD_SERVICE_UNKNOWN;
    }
    return KDD_SERVICE_UNKNOWN;
  }  
  default: return KDD_SERVICE_UNKNOWN;    
  }
}
const char* KDDGetNameService(KDDServiceType t){
  switch (t)
  {
    case KDD_SERVICE_TCP_PRIVATE: return "private";
    case KDD_SERVICE_TCP_FTP_DATA: return "ftp_data";
    case KDD_SERVICE_TCP_TELNET: return "telnet";
    case KDD_SERVICE_TCP_HTTP: return "http";
    case KDD_SERVICE_TCP_SMTP: return "smtp";
    case KDD_SERVICE_TCP_FTP: return "ftp";
    case KDD_SERVICE_TCP_LDAP: return "ldap";
    case KDD_SERVICE_TCP_POP_3: return "pop_3";
    case KDD_SERVICE_TCP_COURIER: return "courier";
    case KDD_SERVICE_TCP_DISCARD: return "discard";
    case KDD_SERVICE_TCP_IMAP4: return "imap4";
    case KDD_SERVICE_TCP_SYSTAT: return "systat";
    //case KDD_SERVICE_TCP_PRIVATE: return "iso_tsap";
    case KDD_SERVICE_TCP_OTHER: return "other";
    case KDD_SERVICE_TCP_CSNET_NS: return "csnet_ns";
    case KDD_SERVICE_TCP_FINGER: return "finger";
    case KDD_SERVICE_TCP_UUCP: return "uucp";
    case KDD_SERVICE_TCP_WHOIS: return "whois";
    case KDD_SERVICE_TCP_NETBIOS_NS: return "netbios_ns";
    case KDD_SERVICE_TCP_LINK: return "link";
    case KDD_SERVICE_TCP_Z39_50: return "Z39_50";
    case KDD_SERVICE_TCP_SUNRPC: return "sunrpc";
    case KDD_SERVICE_TCP_AUTH: return "auth";
    case KDD_SERVICE_TCP_NETBIOS_DGM: return "netbios_dgm";
    case KDD_SERVICE_TCP_UUCP_PATH: return "uucp_path";
    case KDD_SERVICE_TCP_VMNET: return "vmnet";
    case KDD_SERVICE_TCP_DOMAIN: return "domain";
    case KDD_SERVICE_TCP_NAME: return "name";
    case KDD_SERVICE_TCP_POP_2: return "pop_2";
    case KDD_SERVICE_TCP_HTTP_443: return "http_443";
    case KDD_SERVICE_TCP_LOGIN: return "login";
    case KDD_SERVICE_TCP_GOPHER: return "gopher";
    case KDD_SERVICE_TCP_EXEC: return "exec";
    case KDD_SERVICE_TCP_TIME: return "time";
    //case KDD_SERVICE_TCP_PRIVATE: return "remote_job";
    case KDD_SERVICE_TCP_SSH: return "ssh";
    case KDD_SERVICE_TCP_KSHELL: return "kshell";
    case KDD_SERVICE_TCP_SQL_NET: return "sql_net";
    case KDD_SERVICE_TCP_HOSTNAMES: return "hostnames";
    case KDD_SERVICE_TCP_ECHO: return "echo";
    case KDD_SERVICE_TCP_DAYTIME: return "daytime";
    //case KDD_SERVICE_TCP_PRIVATE: return "pm_dump";
    case KDD_SERVICE_TCP_IRC: return "IRC";
    case KDD_SERVICE_TCP_NETSTAT: return "netstat";
    case KDD_SERVICE_TCP_CTF: return "ctf";
    case KDD_SERVICE_TCP_NNTP: return "nntp";
    case KDD_SERVICE_TCP_NETBIOS_SSN: return "netbios_ssn";
    case KDD_SERVICE_TCP_SUPDUP: return "supdup";
    case KDD_SERVICE_TCP_BGP: return "bgp";
    case KDD_SERVICE_TCP_NNSP: return "nnsp";
    case KDD_SERVICE_TCP_RJE: return "rje";
    case KDD_SERVICE_TCP_PRINTER: return "printer";
    case KDD_SERVICE_TCP_EFS: return "efs";
    case KDD_SERVICE_TCP_X11: return "X11";
    case KDD_SERVICE_TCP_KLOGIN: return "klogin";
    case KDD_SERVICE_ICMP_ECO_I: return "eco_i";
    case KDD_SERVICE_ICMP_ECR_I: return "ecr_i";
    case KDD_SERVICE_ICMP_URP_I: return "urp_i";
    case KDD_SERVICE_ICMP_TIM_I: return "tim_i";
    default: return "unknow";    
  }
}

KDDFlagType KDDGetFlag(char* s){
  if (strcmp(s,"REJ") == 0) return KDD_FLAG_REJ;  
  if (strcmp(s,"RSTO") == 0) return KDD_FLAG_RSTO;
  if (strcmp(s,"S0") == 0) return KDD_FLAG_S0;
  if (strcmp(s,"RSTR") == 0) return KDD_FLAG_RSTR;
  if (strcmp(s,"SH") == 0) return KDD_FLAG_SH;
  if (strcmp(s,"S3") == 0) return KDD_FLAG_S3;
  if (strcmp(s,"S2") == 0) return KDD_FLAG_S2;
  if (strcmp(s,"S1") == 0) return KDD_FLAG_S1;
  if (strcmp(s,"RSTOS0") == 0) return KDD_FLAG_RSTOS0;
  if (strcmp(s,"OTH") == 0) return KDD_FLAG_OTH;
  return KDD_FLAG_SF;
}
const char*         KDDGetNameFlag(KDDFlagType t){
  switch (t)
  {
  case KDD_FLAG_REJ: return "REJ";  
  case KDD_FLAG_RSTO: return "RSTO";
  case KDD_FLAG_S0: return "S0";
  case KDD_FLAG_RSTR: return "RSTR";
  case KDD_FLAG_SH: return "SH";
  case KDD_FLAG_S3: return "S3";
  case KDD_FLAG_S2: return "S2";
  case KDD_FLAG_S1: return "S1";
  case KDD_FLAG_RSTOS0: return "RSTOS0";
  case KDD_FLAG_OTH: return "OTH";
  case KDD_FLAG_SF: return "SF";
    default: return "UNKNOW";
  }
}
KDDLabelType KDDGetLabel(char* s){
  if (strcmp(s,"neptune") == 0) return KDD_LABEL_neptune;
  if (strcmp(s,"normal") == 0) return KDD_LABEL_normal;
  if (strcmp(s,"saint") == 0) return KDD_LABEL_saint;
  if (strcmp(s,"mscan") == 0) return KDD_LABEL_mscan;
  if (strcmp(s,"guess_passwd") == 0) return KDD_LABEL_guess_passwd;
  if (strcmp(s,"smurf") == 0) return KDD_LABEL_smurf;
  if (strcmp(s,"apache2") == 0) return KDD_LABEL_apache2;
  if (strcmp(s,"satan") == 0) return KDD_LABEL_satan;
  if (strcmp(s,"buffer_overflow") == 0) return KDD_LABEL_buffer_overflow;
  if (strcmp(s,"back") == 0) return KDD_LABEL_back;
  if (strcmp(s,"warezmaster") == 0) return KDD_LABEL_warezmaster;
  if (strcmp(s,"snmpgetattack") == 0) return KDD_LABEL_snmpgetattack;
  if (strcmp(s,"processtable") == 0) return KDD_LABEL_processtable;
  if (strcmp(s,"pod") == 0) return KDD_LABEL_pod;
  if (strcmp(s,"httptunnel") == 0) return KDD_LABEL_httptunnel;
  if (strcmp(s,"nmap") == 0) return KDD_LABEL_nmap;
  if (strcmp(s,"ps") == 0) return KDD_LABEL_ps;
  if (strcmp(s,"snmpguess") == 0) return KDD_LABEL_snmpguess;
  if (strcmp(s,"ipsweep") == 0) return KDD_LABEL_ipsweep;
  if (strcmp(s,"mailbomb") == 0) return KDD_LABEL_mailbomb;
  if (strcmp(s,"portsweep") == 0) return KDD_LABEL_portsweep;
  if (strcmp(s,"multihop") == 0) return KDD_LABEL_multihop;
  if (strcmp(s,"named") == 0) return KDD_LABEL_named;
  if (strcmp(s,"sendmail") == 0) return KDD_LABEL_sendmail;
  if (strcmp(s,"loadmodule") == 0) return KDD_LABEL_loadmodule;
  if (strcmp(s,"xterm") == 0) return KDD_LABEL_xterm;
  if (strcmp(s,"worm") == 0) return KDD_LABEL_worm;
  if (strcmp(s,"teardrop") == 0) return KDD_LABEL_teardrop;
  if (strcmp(s,"rootkit") == 0) return KDD_LABEL_rootkit;
  if (strcmp(s,"xlock") == 0) return KDD_LABEL_xlock;
  if (strcmp(s,"perl") == 0) return KDD_LABEL_perl;
  if (strcmp(s,"land") == 0) return KDD_LABEL_land;
  if (strcmp(s,"xsnoop") == 0) return KDD_LABEL_xsnoop;
  if (strcmp(s,"sqlattack") == 0) return KDD_LABEL_sqlattack;
  if (strcmp(s,"ftp_write") == 0) return KDD_LABEL_ftp_write;
  if (strcmp(s,"imap") == 0) return KDD_LABEL_imap;
  if (strcmp(s,"udpstorm") == 0) return KDD_LABEL_udpstorm;
  if (strcmp(s,"phf") == 0) return KDD_LABEL_phf;
  return KDD_LABEL_UNKNOWN;
}
const char* KDDGetNameLabel(KDDLabelType t){
  switch (t)
  {
    case KDD_LABEL_neptune: return "neptune";
    case KDD_LABEL_normal: return "normal";
    case KDD_LABEL_saint: return "saint";
    case KDD_LABEL_mscan: return "mscan";
    case KDD_LABEL_guess_passwd: return "guess_passwd";
    case KDD_LABEL_smurf: return "smurf";
    case KDD_LABEL_apache2: return "apache2";
    case KDD_LABEL_satan: return "satan";
    case KDD_LABEL_buffer_overflow: return "buffer_overflow";
    case KDD_LABEL_back: return "back";
    case KDD_LABEL_warezmaster: return "warezmaster";
    case KDD_LABEL_snmpgetattack: return "snmpgetattack";
    case KDD_LABEL_processtable: return "processtable";
    case KDD_LABEL_pod: return "pod";
    case KDD_LABEL_httptunnel: return "httptunnel";
    case KDD_LABEL_nmap: return "nmap";
    case KDD_LABEL_ps: return "ps";
    case KDD_LABEL_snmpguess: return "snmpguess";
    case KDD_LABEL_ipsweep: return "ipsweep";
    case KDD_LABEL_mailbomb: return "mailbomb";
    case KDD_LABEL_portsweep: return "portsweep";
    case KDD_LABEL_multihop: return "multihop";
    case KDD_LABEL_named: return "named";
    case KDD_LABEL_sendmail: return "sendmail";
    case KDD_LABEL_loadmodule: return "loadmodule";
    case KDD_LABEL_xterm: return "xterm";
    case KDD_LABEL_worm: return "worm";
    case KDD_LABEL_teardrop: return "teardrop";
    case KDD_LABEL_rootkit: return "rootkit";
    case KDD_LABEL_xlock: return "xlock";
    case KDD_LABEL_perl: return "perl";
    case KDD_LABEL_land: return "land";
    case KDD_LABEL_xsnoop: return "xsnoop";
    case KDD_LABEL_sqlattack: return "sqlattack";
    case KDD_LABEL_ftp_write: return "ftp_write";
    case KDD_LABEL_imap: return "imap";
    case KDD_LABEL_udpstorm: return "udpstorm";
    case KDD_LABEL_phf: return "phf";
    default: return "UNKNOW";    
  }
}
int64_t KDDCreateKey(KDD_Features* f){
  int64_t key = f->Protocol_Type;
  key = key << 8;
  key = key | f->Service;
  key = key << 16;
  key = key | f->Flag;
  key = key << 8;
  key = key | f->Label;
  return key;
}
void KDDInitRules(KDDRules* rule){
  if (!rule) return; 
  for (int ptc = 0; ptc < KDD_PROTOCOL_MAX; ptc++){
    for (int svc = 0; svc < KDD_SERVICE_TCP_MAX; svc++){
      for (int flg = 0; flg < KDD_FLAG_MAX; flg++){
        for (int lbl = 0; lbl < KDD_LABEL_MAX; lbl++){
          rule->protocols[ptc].services[svc].flags[flg].labels[lbl].top = NULL;
          rule->protocols[ptc].services[svc].flags[flg].labels[lbl].bot = NULL;
        }        
      }      
    }
  }  
}

void KDDAddRule(KDDRules* rule,KDD_Features* f){
  if (!rule || !f) return;
  KDDNode* p = (KDDNode*)malloc(sizeof(KDDNode));
  p->next = NULL;
  p->f = (KDD_Features*)malloc(sizeof(KDD_Features));
  memcpy(p->f,f,sizeof(KDD_Features));
  KDDLabelNode* lblNode = &rule->protocols[f->Protocol_Type].services[f->Service].flags[f->Flag].labels[f->Label];
  if (!lblNode->top){
     lblNode->top = p;     
  }
  else{
    lblNode->bot->next = p;
  } 
  lblNode->bot = p;
  lblNode->count++;
}

void KDDAddMatch(KDDMatchNode* root, KDDLabelNode* lbl){
  if (!root || !lbl) return;
  KDDMatch* m = (KDDMatch*)malloc(sizeof(KDDMatch));
  m->next = NULL;
  m->lblNode = lbl;
  if (!root->top) root->top = m;  
  else root->bot->next = m;
  root->bot = m;
  root->count++;
}
void KDDRemMatch(KDDMatchNode* root){
  if (!root) return;  
  while (root->top){    
    KDDMatch* r = root->top;
    root->top = root->top->next;
    root->count--;
    free(r);
  }  
}

void KDDShowRule(KDDRules* rule){
  if (!rule) return;
  int idx = 0;
  int total = 0;
  for (int ptc = 0; ptc < KDD_PROTOCOL_MAX; ptc++){
    for (int svc = 0; svc < KDD_SERVICE_TCP_MAX; svc++){
      for (int flg = 0; flg < KDD_FLAG_MAX; flg++){
        for (int lbl = 0; lbl < KDD_LABEL_MAX; lbl++){
          if (lbl != KDD_LABEL_portsweep) continue;
          KDDLabelNode* lblNode = &rule->protocols[ptc].services[svc].flags[flg].labels[lbl];
          if (lblNode->count > 0){
            total += lblNode->count;
            printf("%d - [%s:%s:%s:%s] : %d\n",++idx,
            KDDGetNameProtocol(ptc),KDDGetNameService(svc),
            KDDGetNameFlag(flg),KDDGetNameLabel(lbl),lblNode->count);          
          }
        }        
      }      
    }
  }
  printf("TOTAL: %d\n",total);
}
int KDDShowRuleFilter(KDDRules* rule,KDDProtocolType t,KDDServiceType s,KDDFlagType f,KDDLabelType l){
  int total = 0;
  if (l == KDD_LABEL_MAX){
    for (int lbl = 0; lbl < KDD_LABEL_MAX; lbl++){          
      KDDLabelNode* lblNode = &rule->protocols[t].services[s].flags[f].labels[lbl];
      if (lblNode->count > 0){
        total += lblNode->count;
        printf(" [+] [%s:%s:%s:%s] : %d\n",
        KDDGetNameProtocol(t),KDDGetNameService(s),
        KDDGetNameFlag(f),KDDGetNameLabel(lbl),lblNode->count);          
      }
    }
  }
  else{
    KDDLabelNode* lblNode = &rule->protocols[t].services[s].flags[f].labels[l];
    if (lblNode->count > 0){
      total += lblNode->count;
      printf(" [+] [%s:%s:%s:%s] : %d\n",
          KDDGetNameProtocol(t),KDDGetNameService(s),
          KDDGetNameFlag(f),KDDGetNameLabel(l),lblNode->count);
    }
  }

  return total;
}
void KDDShowRuleFilter01(KDDRules* rule,KDDProtocolType t ,KDDServiceType s ,KDDFlagType f){
  
  for (int l = 0; l < KDD_LABEL_MAX; ++l){
    KDDLabelNode* lblNode = &rule->protocols[t].services[s].flags[f].labels[l];
    printf(" [+] [%s:%s:%s:%s] : %d\n",
        KDDGetNameProtocol(t),KDDGetNameService(s),
        KDDGetNameFlag(f),KDDGetNameLabel(l),lblNode->count);
  }
  printf("**KDDShowRuleFilter01**\n");
}
void KDDShowRuleFilter02(KDDRules* rule,KDDProtocolType t,KDDServiceType s,KDDLabelType l){
  int total = 0;
  if (s == KDD_SERVICE_TCP_MAX){
    for (int i = 0; i < KDD_SERVICE_TCP_MAX; i++)
    {
      for (int f = 0; f < KDD_FLAG_MAX; ++f){
        total += KDDShowRuleFilter(rule,t,i,f,l);
        /*KDDLabelNode* lblNode = &rule->protocols[t].services[i].flags[f].labels[l];
        if (lblNode->count > 0){
          total += lblNode->count;
          printf(" [+] [%s:%s:%s:%s] : %d\n",
             KDDGetNameProtocol(t),KDDGetNameService(i),
             KDDGetNameFlag(f),KDDGetNameLabel(l),lblNode->count);
        }*/
      }
    }
  }
  else{
    for (int f = 0; f < KDD_FLAG_MAX; ++f){
      total += KDDShowRuleFilter(rule,t,s,f,l);
      /*KDDLabelNode* lblNode = &rule->protocols[t].services[s].flags[f].labels[l];
      if (lblNode->count > 0){
        total += lblNode->count;
        printf(" [+] [%s:%s:%s:%s] : %d\n",
            KDDGetNameProtocol(t),KDDGetNameService(s),
            KDDGetNameFlag(f),KDDGetNameLabel(l),lblNode->count);
      }*/
    }
  }

  printf("** KDDShowRuleFilter02() : %d **\n",total);
}

void  KDDTrackerEnqueue(KDDTrackerQueue* q, KDDTracker* p){    
    if (q->top != NULL) {
        p->next = q->top;
        q->top->prev = p;
        q->top = p;
    } else {
        q->top = p;
        q->bot = p;
    }
    q->len++;    
}
int KDDTrackerRemove(KDDTrackerQueue* q, KDDTracker* p){
  if (!q || !p) return 0;  

  if (p == q->top){
    if (q->top->next != NULL){
      q->top = q->top->next;
      q->top->prev = NULL;
    }
    else{
      q->top = NULL;
      q->bot = NULL;
    }
  }else{
    if (p == q->bot){
      if (q->bot->prev != NULL) {
        q->bot = q->bot->prev;
        q->bot->next = NULL;        
      } else {
        q->top = NULL;
        q->bot = NULL;
      }
    }
    else{
      if (p->prev) p->prev->next = p->next;
      if (p->next) p->next->prev = p->prev;
      
    }
  }

  if (q->len > 0) q->len--;
  p->next = NULL;
  p->prev = NULL;
  return 0;
}
KDDTracker* KDDTrackerDequeue (KDDTrackerQueue *q){
    FQLOCK_LOCK(q);

    KDDTracker *f = q->bot;
    if (f == NULL) {
        FQLOCK_UNLOCK(q);
        return NULL;
    }
    if (q->bot->prev != NULL) {
        q->bot = q->bot->prev;
        q->bot->next = NULL;
    } else {
        q->top = NULL;
        q->bot = NULL;
    }

    if (q->len > 0) q->len--;
    f->next = NULL;
    f->prev = NULL;
    FQLOCK_UNLOCK(q);
    return f;
}
