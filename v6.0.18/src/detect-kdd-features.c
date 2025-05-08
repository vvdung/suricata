/******************************
 * \author Vo Viet Dung <vvdung@husc.edu.vn>
 ******************************/

#include "suricata-common.h"
#include "tmqh-flow.h"
#include "tmqh-packetpool.h"
#include "tm-queuehandlers.h"
#include "tm-threads.h"
#include "stream-tcp-private.h"
#include "flow-private.h"
#include "detect-kdd-features.h"
#include "source-kdd-features.h"
#include "flow-queue.h"

#define TWO_SECONDS_FROM_MICROSECOND  2000000
#define TCP_ISSET_FLAG_ACKFIN(flag) ((flag & 0x11) == 0x11)
#define TCP_ISSET_FLAG_ACKRST(flag) ((flag & 0x14) == 0x14)
#define MAX_SRCIP_DSTPORT  512

//////////////////////////////////////


///////////////////////////////////////


KDDRules          _rules;
KDDTrackerQueue   _trackerHash;
KDDTracker**      _trackerFlow;
FILE*             _kddFileLog = NULL;
void _DumpHex(uint8_t* pAddress,int iSize){
    if (!pAddress || iSize <= 0){
		SCLogInfo("FAILED! pAddress:[%p] iSize:%d",pAddress,iSize);
		return;
	}
	char ascii[17];
	int i, j;
	ascii[16] = '\0';
	for (i = 0; i < iSize; ++i) {
		printf("%02X ", pAddress[i]);
		if (pAddress[i] >= ' ' && pAddress[i] <= '~') {
			ascii[i % 16] = pAddress[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == iSize) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == iSize) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}
static uint64_t timeval_diff_microseconds(struct timeval *end_time,struct timeval *start_time){

  struct timeval difference;
  difference.tv_sec = end_time->tv_sec -start_time->tv_sec ;
  difference.tv_usec= end_time->tv_usec-start_time->tv_usec;

  /* Using while instead of if below makes the code slightly more robust. */

  while(difference.tv_usec < 0)
  {
    difference.tv_usec += 1000000;
    difference.tv_sec  -=1;
  }
  uint64_t diff_micro = 1000000;
  diff_micro = (diff_micro*difference.tv_sec) + difference.tv_usec;
  return diff_micro;
}
static int IsThresholdTwoSeconds(struct timeval *end_time,struct timeval *start_time){
  uint64_t tDiff = timeval_diff_microseconds(end_time,start_time);
  return (tDiff <= TWO_SECONDS_FROM_MICROSECOND);
}
/*static int IsThresholdTwoSeconds(Packet* p){
  uint64_t tDiff = timeval_diff_microseconds(&p->ts,&p->flow->startts);
  return (tDiff <= TWO_SECONDS_FROM_MICROSECOND);
}*/
static float _Round2(float n){
  float v = (int)(n * 100 + 0.5);
  return (float)v/100;
}

static KDDFlagType KDD_Feature04_Flag(Packet* p){
  if (!PKT_IS_TCP(p)) return KDD_FLAG_SF;
  Flow* flow = p->flow;
  if (!flow) return KDD_FLAG_OTH; //No SYN seen, just midstream traffic
  TcpSession* ssn = (TcpSession*)p->flow->protoctx;
  if (!ssn) return KDD_FLAG_OTH; //No SYN seen, just midstream traffic

  if (ssn->pstate == TCP_NONE && TCP_ISSET_FLAG_SYN(p))
    return KDD_FLAG_S0; //Connection attempt seen, no reply

  if (PKT_IS_TOCLIENT(p)){//OUT
    if (TCP_ISSET_FLAG_RST(p)) {
      if (ssn->pstate == TCP_SYN_SENT)
        return KDD_FLAG_REJ;     //Connection attempt rejected;
      return KDD_FLAG_RSTR; //Connection reset by the responder
    }
    if (ssn->pstate == TCP_ESTABLISHED && TCP_ISSET_FLAG_FIN(p))
      return KDD_FLAG_S3; //Established and close attempt by responder seen (but no reply from originator)
    if (ssn->state == TCP_ESTABLISHED && flow->tosrcbytecnt == 0)
      return KDD_FLAG_S1;      //Established, not terminated
  }
  else{ //IN
    if (TCP_ISSET_FLAG_FIN(p)) {
      if (ssn->pstate == TCP_ESTABLISHED)
        return KDD_FLAG_S2; //Established and close attempt by originator seen (but no reply from responder)
      if (ssn->pstate == TCP_SYN_SENT)
        return KDD_FLAG_SH; //Originator sent a SYN followed by a FIN, we never saw a SYN-ACK from the responder
    }
    if (TCP_ISSET_FLAG_RST(p)) {
      if (ssn->pstate == TCP_SYN_SENT)
        return KDD_FLAG_RSTOS0;  //Originator sent a SYN followed by a RST, we never saw a SYN-ACK from the responder
      return KDD_FLAG_RSTO; //Connection reset by the originator
    }

    if (ssn->state == TCP_ESTABLISHED && flow->todstbytecnt == 0)
     return KDD_FLAG_S1;      //Established, not terminated

  }

  return KDD_FLAG_SF;
}
static KDDFlagType KDDGetFlowFlag(Flow* flow){
  if (!flow) return KDD_FLAG_OTH; //No SYN seen, just midstream traffic
  TcpSession* ssn = (TcpSession*)flow->protoctx;
  if (!ssn) return KDD_FLAG_OTH; //No SYN seen, just midstream traffic
  /*uint8_t prevFlags;
  if (flow->kdd_flowflags & FLOW_PKT_TOCLIENT){
    prevFlags = ssn->client.ptcpFlags;
  }
  else{
    prevFlags = ssn->server.ptcpFlags;
  }
  printf("ssnSTATE[%02X][%02X] tcpFlag[%02X][%02X]\n",
    ssn->pstate,ssn->state,ssn->tcpFlags,prevFlags);*/

  if (ssn->pstate == TCP_NONE && (ssn->tcpFlags & TH_SYN))
    return KDD_FLAG_S0; //Connection attempt seen, no reply

  if (flow->kdd_flowflags & FLOW_PKT_TOCLIENT){//OUT
    if (ssn->tcpFlags & TH_RST) {
      if (ssn->pstate == TCP_SYN_SENT)
        return KDD_FLAG_REJ;     //Connection attempt rejected;
      return KDD_FLAG_RSTR; //Connection reset by the responder
    }
    if (ssn->pstate == TCP_ESTABLISHED && (ssn->tcpFlags & TH_FIN))
      return KDD_FLAG_S3; //Established and close attempt by responder seen (but no reply from originator)
    if (ssn->state == TCP_ESTABLISHED && flow->tosrcbytecnt == 0)
      return KDD_FLAG_S1;      //Established, not terminated
  }
  else{ //IN
    if (ssn->tcpFlags & TH_FIN) {
      if (ssn->pstate == TCP_ESTABLISHED)
        return KDD_FLAG_S2; //Established and close attempt by originator seen (but no reply from responder)
      if (ssn->pstate == TCP_SYN_SENT)
        return KDD_FLAG_SH; //Originator sent a SYN followed by a FIN, we never saw a SYN-ACK from the responder
    }
    if (ssn->tcpFlags & TH_RST) {
      if (ssn->pstate == TCP_SYN_SENT)
        return KDD_FLAG_RSTOS0;  //Originator sent a SYN followed by a RST, we never saw a SYN-ACK from the responder
      return KDD_FLAG_RSTO; //Connection reset by the originator
    }

    if (ssn->state == TCP_ESTABLISHED && flow->todstbytecnt == 0)
     return KDD_FLAG_S1;      //Established, not terminated

  }
  return KDD_FLAG_SF;
}
static int IsFlowClosed(uint32_t hash){
    FlowBucket* fb = &flow_hash[hash];
    if (!fb || fb->next_ts_sc_atomic__ == INT_MAX) return 1;
    else{
       if (!fb->head) return 1;
       else if (!fb->head->protoctx) return 1;
    }
    return 0;
}

static KDDNode* KDDCheckTCPRules(KDDCheckFeatures* chkFeatures,KDDMatchNode* rootMatch, Packet* p){

  KDDMatch* m = rootMatch->top;
  //int bFound1, bFound2;
  while (m){
    for (KDDNode* n = m->lblNode->top; n != NULL; n = n->next){
      //bFound1 = 0; bFound2 = 0;
      if (n->f->Dst_Host_Same_Srv_Rate > 0.0 &&
          chkFeatures->sameDstIP == n->f->Dst_Host_Count){
        float Dst_Host_Same_Srv_Rate = _Round2((float)chkFeatures->sameDstIP_samePort/chkFeatures->sameDstIP);
        float Dst_Host_Diff_Srv_Rate = _Round2((float)chkFeatures->sameDstIP_diffPort/chkFeatures->sameDstIP);
        float Dst_Host_Serror_Rate = _Round2((float)chkFeatures->sameDstIP_FlagSx/chkFeatures->sameDstIP);
        float Dst_Host_Rerror_Rate = _Round2((float)chkFeatures->sameDstIP_FlagREJ/chkFeatures->sameDstIP);

        if (n->f->Dst_Host_Same_Srv_Rate >= Dst_Host_Same_Srv_Rate &&
            n->f->Dst_Host_Diff_Srv_Rate >= Dst_Host_Diff_Srv_Rate &&
            n->f->Dst_Host_Serror_Rate   >= Dst_Host_Serror_Rate &&
            n->f->Dst_Host_Rerror_Rate   >= Dst_Host_Rerror_Rate){
          //bFound1 = 1;
          return n;
        }

        /*SCLogInfo("[%s] [%s] Count_32:%d bFound1:%d\n\
 S[%f] D[%f] Se[%.2f] Re[%.2f]\n\
 S[%f] D[%f] Se[%.2f] Re[%.2f]",
        KDDGetNameLabel(n->f->Label),KDDGetNameService(n->f->Service),
        n->f->Dst_Host_Count,bFound1,
        n->f->Dst_Host_Same_Srv_Rate,n->f->Dst_Host_Diff_Srv_Rate,
        n->f->Dst_Host_Serror_Rate,n->f->Dst_Host_Rerror_Rate,
        Dst_Host_Same_Srv_Rate,Dst_Host_Diff_Srv_Rate,
        Dst_Host_Serror_Rate,Dst_Host_Rerror_Rate);*/

      }//if (chkFeatures->sameDstIP == n->f->Dst_Host_Count){

      if (n->f->Dst_Host_Same_Src_Port_Rate > 0.0 &&
          chkFeatures->sameDstPort == n->f->Dst_Host_Srv_Count){
        float Dst_Host_Same_Src_Port_Rate = _Round2((float)chkFeatures->sameDstPort_sameSrcIP/chkFeatures->sameDstPort);
        float Dst_Host_Srv_Diff_Host_Rate = _Round2((float)chkFeatures->sameDstPort_diffSrcIP/chkFeatures->sameDstPort);
        float Dst_Host_Srv_Serror_Rate = _Round2((float)chkFeatures->sameDstPort_FlagSx/chkFeatures->sameDstPort);
        float Dst_Host_Srv_Rerror_Rate = _Round2((float)chkFeatures->sameDstPort_FlagREJ/chkFeatures->sameDstPort);

        if (n->f->Dst_Host_Same_Src_Port_Rate >= Dst_Host_Same_Src_Port_Rate &&
            n->f->Dst_Host_Srv_Diff_Host_Rate >= Dst_Host_Srv_Diff_Host_Rate &&
            n->f->Dst_Host_Srv_Serror_Rate    >= Dst_Host_Srv_Serror_Rate &&
            n->f->Dst_Host_Srv_Rerror_Rate    >= Dst_Host_Srv_Rerror_Rate){
          //bFound2 = 1;
          return n;
        }

        /*SCLogInfo("[%s] [%s] Count_33:%d bFound2:%d\n\
S[%.2f] D[%.2f] Se[%.2f] Re[%.2f]\n\
S[%.2f] D[%.2f] Se[%.2f] Re[%.2f]",
        KDDGetNameLabel(n->f->Label),KDDGetNameService(n->f->Service),
        n->f->Dst_Host_Srv_Count,bFound2,
        n->f->Dst_Host_Same_Src_Port_Rate,n->f->Dst_Host_Srv_Diff_Host_Rate,
        n->f->Dst_Host_Srv_Serror_Rate,n->f->Dst_Host_Srv_Rerror_Rate,
        Dst_Host_Same_Src_Port_Rate,Dst_Host_Srv_Diff_Host_Rate,
        Dst_Host_Srv_Serror_Rate,Dst_Host_Srv_Rerror_Rate);*/

      }//if (chkFeatures->sameDstPort == n->f->Dst_Host_Srv_Count){

      //if (bFound1 || bFound2){
      //  return n;
      //}
    }//for (KDDNode* n = m->lblNode->top; n != NULL; n = n->next){

    m = m->next;
  }//while (m && !nodeMatch){

  return NULL;
}

static int KDDCheckTCPFeatures(KDDMatchNode* rootMatch, Packet* p, KDDServiceType svcType){
  FQLOCK_LOCK(&_trackerHash);

  KDDCheckFeatures chkFeatures;
  memset(&chkFeatures,0x00,sizeof(KDDCheckFeatures));

  uint32_t curSrcIP   = p->flow->src.address.address_un_data32[0];
  uint32_t curDstIP   = p->flow->dst.address.address_un_data32[0];
  uint16_t curDstPort = p->flow->dp;

  KDDTracker* t = _trackerHash.top;
  KDDNode* nodeMatch = NULL;
  while (t){
    uint32_t hash = t->hash;
    if (IsFlowClosed(hash)){
      KDDTracker* t_nxt = t->next;
      KDDTrackerRemove(&_trackerHash, t);
      free(t);
      _trackerFlow[hash] = NULL;
      t = t_nxt;
      continue;
    }
    FlowBucket* fb = &flow_hash[hash];
    Flow* flow = fb->head;
    //TcpSession* ssn = (TcpSession*)flow->protoctx;
    KDDFlagType flagType = KDDGetFlowFlag(flow);
    int isTwoSeconds = IsThresholdTwoSeconds(&p->ts,&flow->startts);
    int isSameSrcIP = (curSrcIP == flow->src.address.address_un_data32[0]);
    int isSameDstIP = (curDstIP == flow->dst.address.address_un_data32[0]);
    int isSameDstPort = (curDstPort == flow->dp);
    int isFlagREJ = (flagType >= KDD_FLAG_REJ && flagType <= KDD_FLAG_SH);
    int isFlagSx = (flagType >= KDD_FLAG_S0 && flagType <= KDD_FLAG_S3);

    if (isTwoSeconds){
      chkFeatures.totalConnection_2s++;
      if (isSameDstIP){
        chkFeatures.sameDstIP_2s++;
        if (isSameDstPort) chkFeatures.sameDstIP_2s_samePort++;
        else chkFeatures.sameDstIP_2s_diffPort++;

        if (isFlagREJ) chkFeatures.sameDstIP_2s_FlagREJ++;
        if (isFlagSx) chkFeatures.sameDstIP_2s_FlagSx++;
      }

      if (isSameDstPort){
        chkFeatures.sameDstPort_2s++;
        if (isFlagREJ) chkFeatures.sameDstPort_2s_FlagREJ++;
        if (isFlagSx) chkFeatures.sameDstPort_2s_FlagSx++;
        if (!isSameDstIP) chkFeatures.sameDstPort_2s_diffDstIP++;
      }

    }//if (isTwoSeconds)

    if (isSameDstPort){
      chkFeatures.sameDstPort++;
      if (isSameSrcIP) chkFeatures.sameDstPort_sameSrcIP++;
      else chkFeatures.sameDstPort_diffSrcIP++;
      if (isFlagREJ) chkFeatures.sameDstPort_FlagREJ++;
      if (isFlagSx) chkFeatures.sameDstPort_FlagSx++;
    }

    if (isSameDstIP){
      chkFeatures.sameDstIP++;//multi src -> one dst
      if (isSameDstPort){
         chkFeatures.sameDstIP_samePort++;
         if (isSameSrcIP) chkFeatures.sameSrcIP_DstIP_DstPort++;
      }
      else chkFeatures.sameDstIP_diffPort++;
      if (isFlagREJ) chkFeatures.sameDstIP_FlagREJ++;
      if (isFlagSx) chkFeatures.sameDstIP_FlagSx++;
    }

    chkFeatures.totalConnection++;
    if (chkFeatures.sameSrcIP_DstIP_DstPort >= MAX_SRCIP_DSTPORT) break;
    //printf("index: %d flag[%s]\n",chkFeatures.totalConnection,KDDGetNameFlag(flagType));
    nodeMatch = KDDCheckTCPRules(&chkFeatures,rootMatch,p);
    if (nodeMatch) break;
    t = t->next;
  }//while (t){

  if (chkFeatures.totalConnection_2s && nodeMatch){

    //SCLogNotice(">>> MATCH COUNT:%d Connections: %d [%d/%d] => isMatch:%d",
    //rootMatch->count,chkFeatures.sameSrcIP_DstIP_DstPort,chkFeatures.totalConnection,_trackerHash.len,nodeMatch != NULL);
    uint8_t* srcIP = (uint8_t*)p->flow->src.address.address_un_data8;
    uint8_t* dstIP = (uint8_t*)p->flow->dst.address.address_un_data8;
    //uint8_t direct = FlowGetPacketDirection(p->flow,p); //TOSERVER = 0, TOCLIENT=1
    char timebuf[64];
    char kddBuffer[1024];
    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));
    int iLen = snprintf(kddBuffer,1024,"%s => CLASSIFIED (%s) [%d.%d.%d.%d:%d => %d.%d.%d.%d:%d] [%s]\n",
      timebuf,
      KDDGetNameLabel(nodeMatch->f->Label),
      srcIP[0],srcIP[1],srcIP[2],srcIP[3],p->flow->sp,
      dstIP[0],dstIP[1],dstIP[2],dstIP[3],p->flow->dp,
      KDDGetNameService(svcType));
    if (iLen > 0){
       //fwrite(kddBuffer,iLen,_kddFileLog);
       fprintf(_kddFileLog,"%s",kddBuffer);
       fflush(_kddFileLog);
    }
    SCLogError(">>> [%d] MATCH KDD FEATURE => CLASSIFIED (%s) [%d.%d.%d.%d:%d => %d.%d.%d.%d:%d] [%s]",
      iLen,KDDGetNameLabel(nodeMatch->f->Label),
      srcIP[0],srcIP[1],srcIP[2],srcIP[3],p->flow->sp,
      dstIP[0],dstIP[1],dstIP[2],dstIP[3],p->flow->dp,
      KDDGetNameService(svcType));

    /*printf("\
  \n SECOND 23 dstIP:%d samePort:%d diffPort:%d FlagR[%d] FlagS[%d]\
  \n SECOND 24 dstIP:%d diffDstIP:%d            FlagR[%d] FlagS[%d]\
  \n TOTAL  32 dstIP:%d samePort:%d diffPort:%d FlagR[%d] FlagS[%d]\
  \n TOTAL  33 dstIP:%d samePort:%d diffPort:%d FlagR[%d] FlagS[%d]\n",
      chkFeatures.sameDstIP_2s,
      chkFeatures.sameDstIP_2s_samePort,chkFeatures.sameDstIP_2s_diffPort,
      chkFeatures.sameDstIP_2s_FlagREJ,chkFeatures.sameDstIP_2s_FlagSx,

      chkFeatures.sameDstPort_2s,
      chkFeatures.sameDstPort_2s_diffDstIP,
      chkFeatures.sameDstPort_2s_FlagREJ,chkFeatures.sameDstPort_2s_FlagSx,

      chkFeatures.sameDstIP,
      chkFeatures.sameDstIP_samePort,chkFeatures.sameDstIP_diffPort,
      chkFeatures.sameDstIP_FlagREJ,chkFeatures.sameDstIP_FlagSx,

      chkFeatures.sameDstPort,
      chkFeatures.sameDstPort_sameSrcIP,chkFeatures.sameDstPort_diffSrcIP,
      chkFeatures.sameDstPort_FlagREJ,chkFeatures.sameDstPort_FlagSx);*/
  }//if (chkFeatures.totalConnection_2s && nodeMatch){

  FQLOCK_UNLOCK(&_trackerHash);

  return 0;
}
static void KDDCheckTCPRuleMatch(KDDProtocolType t,Packet* p){
  Flow* flow = p->flow;
  KDDServiceType  s = KDDGetServiceType(t,flow->dp);
  KDDFlagType f = KDD_Feature04_Flag(p);

  KDDMatchNode rootMatch;
  memset(&rootMatch,0x00,sizeof(KDDMatchNode));

  for (int i = 0; i < KDD_LABEL_MAX; i++){
    KDDLabelNode* lblNode = &_rules.protocols[t].services[s].flags[f].labels[i];
    if (lblNode->count <= 0) continue;
    KDDAddMatch(&rootMatch,lblNode);
  }

  if (rootMatch.count){
    KDDCheckTCPFeatures(&rootMatch,p,s);
    KDDRemMatch(&rootMatch);
  }
}
static void KDDCheckUDPRuleMatch(KDDProtocolType t,Packet* p){
  Flow* flow = p->flow;
  KDDServiceType  s = KDDGetServiceType(t,flow->dp);
  SCLogInfo("protocol:[%s] service:[%s]",KDDGetNameProtocol(t),KDDGetNameService(s));
}
static void KDDCheckICMPRuleMatch(KDDProtocolType t,Packet* p){
  Flow* flow = p->flow;
  KDDServiceType  s = KDDGetServiceType(t,flow->dp);
  SCLogInfo("protocol:[%s] service:[%s]",KDDGetNameProtocol(t),KDDGetNameService(s));
}
static void KDDCheckRuleMatch(Packet* p){
  if (!p) return;
  Flow* flow = p->flow;
  if (!flow) return;
  KDDProtocolType t = KDDGetProtocolType(p->proto);
  switch (t)
  {
  case KDD_PROTOCOL_TCP:  KDDCheckTCPRuleMatch(t,p); break;
  case KDD_PROTOCOL_UDP:  KDDCheckUDPRuleMatch(t,p); break;
  case KDD_PROTOCOL_ICMP: KDDCheckICMPRuleMatch(t,p); break;
  default: return;
  }
}


//////////////////////////////////////////////
/*static const char* SessionFlagToString(uint8_t flag){
  switch (flag)
  {
    case TCP_NONE:        return "TCP_NONE";
    case TCP_LISTEN:      return "TCP_LISTEN";
    case TCP_SYN_SENT:    return "TCP_SYN_SENT";
    case TCP_SYN_RECV:    return "TCP_SYN_RECV";
    case TCP_ESTABLISHED: return "TCP_ESTABLISHED";
    case TCP_FIN_WAIT1:   return "TCP_FIN_WAIT1";
    case TCP_FIN_WAIT2:   return "TCP_FIN_WAIT2";
    case TCP_TIME_WAIT:   return "TCP_TIME_WAIT";
    case TCP_LAST_ACK:    return "TCP_LAST_ACK";
    case TCP_CLOSE_WAIT:  return "TCP_CLOSE_WAIT";
    case TCP_CLOSING:     return "TCP_CLOSING";
    case TCP_CLOSED:      return "TCP_CLOSED";
    default:
      return "TCP_UNKNOW";
  }
}
*/
void KDD_Init_PacketHandler(void* threadVars){
  ThreadVars *tv = (ThreadVars *)threadVars;
  //tv->kdds = SCMalloc(sizeof(KDDFeatures));
  //memset(tv, 0, sizeof(KDDFeatures));

  SCLogInfo("[KDD] PPT PacketHandler(%p): %d ", tv,tv->id);

  /*printf("[-] perf_public_ctx.curr_id:%d \n",tv->perf_public_ctx.curr_id);
  StatsCounter* pCounter = tv->perf_public_ctx.head;
  while (pCounter){
    printf(" [+] id:%hu gid:%hu type:%d [%s] v:%lu u:%lu\n",
    pCounter->id,pCounter->gid,pCounter->type,pCounter->name,
    pCounter->value,pCounter->updates);

    pCounter = pCounter->next;
  }

  printf("[-] perf_private_ctx.initialized:%d size:%d\n",tv->perf_private_ctx.initialized,tv->perf_private_ctx.size);
  pCounter = tv->perf_private_ctx.head;
  while (pCounter){
    printf(" [+] id:%hu gid:%hu type:%d [%s] v:%lu u:%lu\n",
    pCounter->id,pCounter->gid,pCounter->type,pCounter->name,
    pCounter->value,pCounter->updates);

    pCounter = pCounter->next;
  }*/
}


static bool KDDTrackerDel(uint32_t hash){
  FQLOCK_LOCK(&_trackerHash);
  KDDTracker* t = _trackerFlow[hash];
  if (!t){
    //SCLogError(1,"??? t == NULL hash[%u] COUNT:%u",hash,_trackerHash.len);
    FQLOCK_UNLOCK(&_trackerHash);
    return false;
  }
  KDDTrackerRemove(&_trackerHash, t);
  free(t);
  _trackerFlow[hash] = NULL;
  FQLOCK_UNLOCK(&_trackerHash);
  return true;
}

static void KDDTrackerAdd(uint32_t hash){
  FQLOCK_LOCK(&_trackerHash);
  KDDTracker* t = _trackerFlow[hash];
  if (t) KDDTrackerRemove(&_trackerHash, t);
  else t = (KDDTracker*)malloc(sizeof(KDDTracker));

  memset(t,0x00,sizeof(KDDTracker));
  t->hash = hash;
  KDDTrackerEnqueue(&_trackerHash,t);
  _trackerFlow[hash] = t;
  FQLOCK_UNLOCK(&_trackerHash);
}

static void KDDTrackerPrint(void){
  FQLOCK_LOCK(&_trackerHash);
  KDDTracker* t = _trackerHash.top;
  uint32_t cnt = 0;
  while (t){
    uint32_t hash = t->hash;

    if (IsFlowClosed(hash)){
      KDDTracker* p = t->next;
      KDDTrackerRemove(&_trackerHash, t);
      free(t);
      _trackerFlow[hash] = NULL;
      t = p;
      continue;
    }

    ++cnt;
    /*FlowBucket* fb = &flow_hash[hash];
    Flow* flow = fb->head;
    TcpSession* ssn = (TcpSession*)flow->protoctx;

    printf("%6d  [%u] FLOW[%p] state[%hu] cnt:%d SSN[%p] state[%02X][%02X]\n",
            cnt,hash,
            flow,flow->flow_state,flow->use_cnt,
            ssn,ssn->pstate,ssn->state);*/

    t = t->next;
  }
  FQLOCK_UNLOCK(&_trackerHash);
}

#define FLAG_ACK_SYN 0x12//(TH_ACK || TH_SYN)

static void KDD_Update_Features_TCP(ThreadVars* tv, DetectEngineCtx *de_ctx, Packet* p){

  u_char* ipSrc = (u_char*)&p->ip4h->s_ip_src.s_addr;
  u_char* ipDst = (u_char*)&p->ip4h->s_ip_dst.s_addr;
  ushort portSrc = TCP_GET_SRC_PORT(p);
  ushort portDst = TCP_GET_DST_PORT(p);

  Flow* flow = p->flow;
  if (!flow){
    // SCLogNotice("* TCP TID:%d hash[%u] [%d.%d.%d.%d:%d]->[%d.%d.%d.%d:%d] FLOW NULL",
    // tv->id,p->flow_hash%flow_config.hash_size,
    // ipSrc[0],ipSrc[1],ipSrc[2],ipSrc[3],portSrc,
    // ipDst[0],ipDst[1],ipDst[2],ipDst[3],portDst);
    return;
  }

  if (p->flow_hash != flow->flow_hash) return;

  uint32_t hash = p->flow_hash % flow_config.hash_size;

  TcpSession* ssn = (TcpSession*)p->flow->protoctx;
  if (!ssn){
    // SCLogNotice("* TCP TID:%d hash[%u] [%d.%d.%d.%d:%d]->[%d.%d.%d.%d:%d] SESSION NULL",
    // tv->id,hash,
    // ipSrc[0],ipSrc[1],ipSrc[2],ipSrc[3],portSrc,
    // ipDst[0],ipDst[1],ipDst[2],ipDst[3],portDst);
    return;
  }

  //FlowBucket* fb = flow->fb;  
  //uint8_t prevFlags,currFlags;
  uint8_t direct = FlowGetPacketDirection(flow,p);
  uint8_t statusFlow = FLOW_STATE_ESTABLISHED;
  char czIO[32];
  flow->kdd_flowflags = p->flowflags;

  if (direct == TOSERVER){
    strcpy(czIO,"=> SERVER");
    ssn->server.ptcpFlags = ssn->tcpFlags;
    ssn->tcpFlags = p->tcph->th_flags;
    //prevFlags = ssn->server.ptcpFlags; currFlags = ssn->tcpFlags;    

    // if (flow->flow_state == FLOW_STATE_NEW){
    //   statusFlow = FLOW_STATE_NEW;
    // }else if (flow->flow_state == FLOW_STATE_CLOSED){
    //     if(ssn->tcpFlags & (FLAG_ACK_SYN) ) statusFlow = FLOW_STATE_NEW;
    //     else{
    //       if (ssn->state == TCP_CLOSED) statusFlow = FLOW_STATE_CLOSED;
    //     }
    // }
  }
  else{
    strcpy(czIO,"=> CLIENT");
    ssn->client.ptcpFlags = ssn->tcpFlags;
    ssn->tcpFlags = p->tcph->th_flags;    
    //prevFlags = ssn->client.ptcpFlags; currFlags = ssn->tcpFlags;

    if (flow->flow_state == FLOW_STATE_NEW){
      if(ssn->tcpFlags == FLAG_ACK_SYN) statusFlow = FLOW_STATE_NEW;
    }
    else if (flow->flow_state == FLOW_STATE_CLOSED) statusFlow = FLOW_STATE_CLOSED;

    // if (flow->flow_state == FLOW_STATE_CLOSED){
    //   if (ssn->state == TCP_CLOSED) statusFlow = FLOW_STATE_CLOSED;
    // }

  }

  // if(ssn->tcpFlags == FLAG_ACK_SYN ) statusFlow = FLOW_STATE_NEW;
  // else if (flow->flow_state == FLOW_STATE_CLOSED) statusFlow = FLOW_STATE_CLOSED;

  if (statusFlow == FLOW_STATE_NEW) {
    // if (flow->dp == 445){
    //   SCLogNotice("*** DROP PORT 445 ***");
    //   p->action = ACTION_DROP;
    //   return;
    // }

    KDDTrackerAdd(hash);

    SCLogNotice("*** SESSION FIRST [%p] hash[%u] [%d.%d.%d.%d:%d]->[%d.%d.%d.%d:%d] ssnState[%02X][%02X] tcpFlags[%02X][%02X] ref_cnt:%d %u",
              flow,hash,
              ipSrc[0],ipSrc[1],ipSrc[2],ipSrc[3],portSrc,
              ipDst[0],ipDst[1],ipDst[2],ipDst[3],portDst,
              ssn->pstate,ssn->state,
              prevFlags,currFlags,flow->use_cnt,_trackerHash.len);*/      
            
  }

  //KDDCheckRuleMatch(p);

  /*printf(" %s flow[%p] hash[%u] statusFlow[%d] [%d.%d.%d.%d:%d]<->[%d.%d.%d.%d:%d] flow_state:[%hu][%hu] ssnFlags[%02X][%02X] tcpFlags[%02X][%02X] Act:%d\n",
      czIO,flow,hash,statusFlow,
      ipSrc[0],ipSrc[1],ipSrc[2],ipSrc[3],portSrc,
      ipDst[0],ipDst[1],ipDst[2],ipDst[3],portDst,
      flow->flow_state,flow->use_cnt,
      ssn->pstate,ssn->state,
      prevFlags,currFlags,p->action);
  if (flow->dp == 23 && p->payload_len) _DumpHex(p->payload,p->payload_len);*/


  if (statusFlow == FLOW_STATE_CLOSED){
      KDDTrackerDel(hash);
      /*SCLogNotice("*** SESSION CLOSE [%p] hash[%u] [%d.%d.%d.%d:%d]->[%d.%d.%d.%d:%d] ssnState[%02X][%02X] tcpFlags[%02X][%02X] ref_cnt:%d %d",
          flow,hash,
          ipSrc[0],ipSrc[1],ipSrc[2],ipSrc[3],portSrc,
          ipDst[0],ipDst[1],ipDst[2],ipDst[3],portDst, 
          ssn->pstate,ssn->state,
          prevFlags,currFlags,flow->use_cnt,_trackerHash.len);*/       
  }

}//void KDD_Update_Features_TCP(void* threadVars, void* packet){

static void KDD_Update_Features_UDP(ThreadVars *tv, Packet* p){
  return;
  u_char* ipSrc = (u_char*)&p->ip4h->s_ip_src.s_addr;
  u_char* ipDst = (u_char*)&p->ip4h->s_ip_dst.s_addr;
  ushort portSrc = UDP_GET_SRC_PORT(p);
  ushort portDst = UDP_GET_DST_PORT(p);
  SCLogInfo("UDP tid:%d [%d.%d.%d.%d:%d]->[%d.%d.%d.%d:%d] [%p] Payload:%d Flow[%p]",
                tv->id,
                ipSrc[0],ipSrc[1],ipSrc[2],ipSrc[3],portSrc,
                ipDst[0],ipDst[1],ipDst[2],ipDst[3],portDst,
                p,p->payload_len,p->flow);
}

static void KDD_Update_Features_ICMP(ThreadVars *tv, Packet* p){

  Flow* flow = p->flow;
  FlowBucket* fb = flow->fb;

  u_char* ipSrc = (u_char*)&p->ip4h->s_ip_src.s_addr;
  u_char* ipDst = (u_char*)&p->ip4h->s_ip_dst.s_addr;

  //if (p->flowflags & FLOW_PKT_TOSERVER_FIRST){
    //SCLogNotice("*** ICMPv4 IN => FIRST ");
  //}

  char czIO[10];
  if (PKT_IS_TOSERVER(p)) strcpy(czIO,"=> IN ");
  else strcpy(czIO,"<= OUT");

  if (p->payload_len == 64){
    if (p->icmpv4h->type != 8) return;

    SCLogNotice("*** TCP LIST FlowBucket FLOW");
    uint32_t count = 0;
    uint8_t prevFlags = 0,currFlags = 0;

    for (uint32_t i = 0; i < flow_config.hash_size; ++i){
      fb = &flow_hash[i];
      if (!fb || fb->next_ts_sc_atomic__ == INT_MAX) continue;
      flow = fb->head;
      if (!flow || flow->proto != IPPROTO_TCP) continue;
      //uint8_t* srcIP = (uint8_t*)flow->src.address.address_un_data8;
      //uint8_t* dstIP = (uint8_t*)flow->dst.address.address_un_data8;
      uint32_t srcPort = (uint32_t)flow->sp;
      uint32_t dstPort = (uint32_t)flow->dp;

      TcpSession* ssn = (TcpSession*)flow->protoctx;
      if (!ssn){
        SCLogNotice("* hash[%u] [%d.%d.%d.%d:%d]->[%d.%d.%d.%d:%d] SESSION NULL [%02X][%02X]",
        i,
        ipSrc[0],ipSrc[1],ipSrc[2],ipSrc[3],srcPort,
        ipDst[0],ipDst[1],ipDst[2],ipDst[3],dstPort,
        currFlags,prevFlags);
        continue;
      }

      currFlags = ssn->tcpFlags;
      if (flow->kdd_flowflags & FLOW_PKT_TOSERVER) prevFlags = ssn->server.ptcpFlags;
      else prevFlags = ssn->client.ptcpFlags;

      ++count;
      /*printf("%6d [+] [%u] cnt:%d flow_state[%hu] [%d.%d.%d.%d:%d]<=>[%d.%d.%d.%d:%d] ssnState[%02X][%02X] tcpFlags[%02X][%02X]\n",
        count,i,flow->use_cnt,flow->flow_state,
        srcIP[0],srcIP[1],srcIP[2],srcIP[3],srcPort,
        dstIP[0],dstIP[1],dstIP[2],dstIP[3],dstPort,
        ssn->pstate,ssn->state,
        prevFlags,currFlags);*/
    }//for (uint32_t i = 0; i < flow_config.hash_size; ++i){
    //KDDTrackerFlowSocketPrint();
    KDDTrackerPrint();
    if (count > 0) SCLogNotice("*** FlowBuckets COUNT:%u Trackers[%u]",count,_trackerHash.len);
    return;
  }

  /*SCLogInfo("ICMPv4 tid:%d (%s) flowflags:%02X hash:[%u] flow[%p] state[%04X] cnt:%hu end_flags[%02X] \n \
fb[%p] type:%d code:%d [%d.%d.%d.%d]->[%d.%d.%d.%d]",
              tv->id,czIO,p->flowflags,p->flow_hash%flow_config.hash_size,flow,
              flow->flow_state,flow->use_cnt, flow->flow_end_flags,
              fb,p->icmpv4h->type,p->icmpv4h->code,
              ipSrc[0],ipSrc[1],ipSrc[2],ipSrc[3],
              ipDst[0],ipDst[1],ipDst[2],ipDst[3]);*/

  /*SCLogInfo("ICMPv4 tid:%d [%d.%d.%d.%d]->[%d.%d.%d.%d] Payload:%d type:%d code:%d flow_hash:[%u]Flow[%p]",
              tv->id,
              ipSrc[0],ipSrc[1],ipSrc[2],ipSrc[3],
              ipDst[0],ipDst[1],ipDst[2],ipDst[3],
              p->payload_len,p->icmpv4h->type,p->icmpv4h->code,
              p->flow_hash%flow_config.hash_size,flow);*/

}//void KDD_Update_Features_ICMP(void* threadVars, void* packet){

void KDD_IPOnlyInit(void* detectEngineCtx){
  DetectEngineCtx *de_ctx = detectEngineCtx;
  SCLogNotice("[KDD] KDD_IPOnlyInit(%p) ***",de_ctx);
}

static void KDDLoadRules(void){
  SCLogNotice("=== LOAD KDD RULES ===");
  char czFile[PATH_MAX] = "/var/kdd/kddtest.txt";
  // if (!getcwd(czFile, PATH_MAX)) {
  //   SCLogError(SC_ERR_SPRINTF,"getcwd()");
  //   return;
  // }
  // strcat(czFile,"/ohm/kddtest.txt");
  SCLogNotice("LOADING KDD TEST [%s]",czFile);
  FILE* f = fopen(czFile,"r");
  if (!f){
    SCLogError(SC_ERR_OPENING_RULE_FILE,"Open File [%s]!",czFile);
    return;
  }

  char czLine[512];
    KDD_Features features;
  memset(&features,0x00,sizeof(KDD_Features));
  while(fgets(czLine, 512, f)) {

    if (strlen(czLine) <= 0) continue;
    //char* pRow = strdup(czLine);

    char *p = strtok (czLine,",");
    char* arrFeature[MAX_KDD_FEATURES];
    int i = 0;
    while (p != NULL)
    {
      if (i < MAX_KDD_FEATURES){
        arrFeature[i++] = p;
      }
      else break;
      p = strtok (NULL, ",");
    }
    features.Label              = KDDGetLabel(arrFeature[41]);
    if (features.Label == KDD_LABEL_normal) continue;

    features.Duration           = atoi(arrFeature[0]);
    features.Protocol_Type      = KDDGetProtocol(arrFeature[1]);
    features.Service            = KDDGetService(features.Protocol_Type,arrFeature[2]);
    features.Flag               = KDDGetFlag(arrFeature[3]);
    features.Src_Bytes          = atoi(arrFeature[4]);
    features.Dst_Bytes          = atoi(arrFeature[5]);
    features.Land               = atoi(arrFeature[6]);
    features.Wrong_Fragment     = atoi(arrFeature[7]);
    features.Urgent             = atoi(arrFeature[8]);
    features.Hot                = atoi(arrFeature[9]);
    features.Num_Failed_Logins  = atoi(arrFeature[10]);
    features.Logged_In          = atoi(arrFeature[11]);
    features.Num_Compromised    = atoi(arrFeature[12]);
    features.Root_Shell         = atoi(arrFeature[13]);
    features.Su_Attempted       = atoi(arrFeature[14]);
    features.Num_Root           = atoi(arrFeature[15]);
    features.Num_File_Creations = atoi(arrFeature[16]);
    features.Num_Shells         = atoi(arrFeature[17]);
    features.Num_Access_Files   = atoi(arrFeature[18]);
    features.Num_Outbound_Cmds  = atoi(arrFeature[19]);
    features.Is_Hot_Logins      = atoi(arrFeature[20]);
    features.Is_Guest_Login     = atoi(arrFeature[21]);
    features.Count              = atoi(arrFeature[22]);
    features.Srv_Count          = atoi(arrFeature[23]);
    features.Serror_Rate        = atof(arrFeature[24]);
    features.Srv_Serror_Rate    = atof(arrFeature[25]);
    features.Rerror_Rate        = atof(arrFeature[26]);
    features.Srv_Rerror_Rate    = atof(arrFeature[27]);
    features.Same_Srv_Rate      = atof(arrFeature[28]);
    features.Diff_Srv_Rate      = atof(arrFeature[29]);
    features.Srv_Diff_Host_Rate = atof(arrFeature[30]);
    features.Dst_Host_Count     = atoi(arrFeature[31]);
    features.Dst_Host_Srv_Count = atoi(arrFeature[32]);
    features.Dst_Host_Same_Srv_Rate       = atof(arrFeature[33]);
    features.Dst_Host_Diff_Srv_Rate       = atof(arrFeature[34]);
    features.Dst_Host_Same_Src_Port_Rate  = atof(arrFeature[35]);
    features.Dst_Host_Srv_Diff_Host_Rate  = atof(arrFeature[36]);
    features.Dst_Host_Serror_Rate         = atof(arrFeature[37]);
    features.Dst_Host_Srv_Serror_Rate     = atof(arrFeature[38]);
    features.Dst_Host_Rerror_Rate         = atof(arrFeature[39]);
    features.Dst_Host_Srv_Rerror_Rate     = atof(arrFeature[40]);

    KDDAddRule(&_rules,&features);

    //free(pRow);
  }//while(fgets(czLine, 512, f)) {

  fclose(f);
}
void KDD_Initialization(void){
  SCLogNotice("*** KDD INITIALIZATION ***");

  KDDInitRules(&_rules);
  KDDLoadRules();

  memset(&_trackerHash,0x00,sizeof(KDDTrackerQueue));
  FQLOCK_INIT(&_trackerHash);
  uint32_t uSize = flow_config.hash_size * sizeof(KDDTracker*);
  _trackerFlow = (KDDTracker**)malloc(uSize);
  memset(_trackerFlow,0x00,uSize);

  
  char czFile[PATH_MAX] = "/var/kdd/kdd.log";
  // if (!getcwd(czFile, PATH_MAX)) {
  //   SCLogError(SC_ERR_SPRINTF,"getcwd()");
  //   return;
  // }
  // strcat(czFile,"/ohm/logs/kdd.log");
  SCLogNotice("=== KDD LOG === [%s]",czFile);
  _kddFileLog = fopen(czFile,"a+");
  if (!_kddFileLog){
    SCLogError(SC_ERR_OPENING_RULE_FILE,"Open File [%s]!",czFile);
    return;
  }

  //SCLogNotice("*** _trackerFlow[%p] hash_size:%d uSize:%d***",_trackerFlow,flow_config.hash_size,uSize);
  //KDDShowRuleFilter02(&_rules,KDD_PROTOCOL_TCP,KDD_SERVICE_TCP_HTTP,KDD_LABEL_MAX);
}


void KDD_Update_Features(void* threadVars,void *de, void *det, void* packet){
  ThreadVars *tv = (ThreadVars *)threadVars;
  DetectEngineCtx *de_ctx = (DetectEngineCtx *)de;
 // DetectEngineThreadCtx* det_ctx = (DetectEngineThreadCtx*)det;
  Packet* p = (Packet*)packet;
  if (!tv || tv->type != TVT_PPT) return;
  //if (!tv || tv->type != TVT_PPT || !tv->kdds) return;

  /*switch (p->action)
  {
    case ACTION_DROP:
    case ACTION_REJECT:
    case ACTION_REJECT_DST:
    case ACTION_REJECT_BOTH:
        return;
  }*/
  if (!(p->action == 0 || p->action == ACTION_PASS || p->action == ACTION_ALERT)) return;
  /*if (PKT_IS_IPV4(p)){
    KDD_Update_Features_IP4(tv,de_ctx,det_ctx,p);
    return;
  }
  return;*/

  if (!PKT_IS_IPV4(p)) return;
  //KDDFeatures* kdd = tv->kdds;

  if (PKT_IS_TCP(p)){
    KDD_Update_Features_TCP(tv,de_ctx,p);
    return;
  }//if (PKT_IS_TCP(p)){

  if (PKT_IS_UDP(p)){
    KDD_Update_Features_UDP(tv,p);
    return;
  }

  if (PKT_IS_ICMPV4(p)){
    KDD_Update_Features_ICMP(tv,p);
    return;
  }
}//void KDDUpdate(void* pTV, void* pck){
